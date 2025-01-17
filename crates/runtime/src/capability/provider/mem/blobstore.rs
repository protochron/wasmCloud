use crate::capability::{self, blobstore};

use core::ops::RangeInclusive;

use std::collections::{hash_map, BTreeMap, HashMap};
use std::io::Cursor;
use std::num::NonZeroUsize;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context};
use async_trait::async_trait;
use futures::{stream, Stream};
use tokio::io::{self, AsyncRead, AsyncReadExt};
use tokio::sync::RwLock;
use tracing::instrument;

#[derive(Debug)]
/// In-memory [`Blobstore`] [`Container`] object
pub struct Object {
    data: Vec<u8>,
    created_at: SystemTime,
}

impl From<Vec<u8>> for Object {
    fn from(data: Vec<u8>) -> Self {
        Self {
            data,
            created_at: SystemTime::now(),
        }
    }
}

impl AsRef<[u8]> for Object {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Default for Object {
    fn default() -> Self {
        vec![].into()
    }
}

/// In-memory [`Blobstore`] container
#[derive(Debug)]
pub struct Container {
    objects: HashMap<String, Object>,
    created_at: SystemTime,
}

impl Default for Container {
    fn default() -> Self {
        Self {
            objects: HashMap::default(),
            created_at: SystemTime::now(),
        }
    }
}

/// In-memory [`Blobstore`](crate::capability::Blobstore) implementation
#[derive(Debug, Default)]
pub struct Blobstore(RwLock<HashMap<String, RwLock<Container>>>);

impl FromIterator<(String, RwLock<Container>)> for Blobstore {
    fn from_iter<T: IntoIterator<Item = (String, RwLock<Container>)>>(iter: T) -> Self {
        Self(RwLock::new(iter.into_iter().collect()))
    }
}

impl FromIterator<(String, Container)> for Blobstore {
    fn from_iter<T: IntoIterator<Item = (String, Container)>>(iter: T) -> Self {
        Self(RwLock::new(
            iter.into_iter().map(|(k, v)| (k, RwLock::new(v))).collect(),
        ))
    }
}

impl From<HashMap<String, Container>> for Blobstore {
    fn from(kv: HashMap<String, Container>) -> Self {
        kv.into_iter().collect()
    }
}

impl From<HashMap<String, RwLock<Container>>> for Blobstore {
    fn from(kv: HashMap<String, RwLock<Container>>) -> Self {
        kv.into_iter().collect()
    }
}

#[allow(clippy::implicit_hasher)]
impl From<Blobstore> for HashMap<String, Container> {
    fn from(Blobstore(kv): Blobstore) -> Self {
        kv.into_inner()
            .into_iter()
            .map(|(k, v)| (k, v.into_inner()))
            .collect()
    }
}

impl From<Blobstore> for BTreeMap<String, Container> {
    fn from(Blobstore(kv): Blobstore) -> Self {
        kv.into_inner()
            .into_iter()
            .map(|(k, v)| (k, v.into_inner()))
            .collect()
    }
}

impl IntoIterator for Blobstore {
    type Item = (String, Container);
    type IntoIter = hash_map::IntoIter<String, Container>;

    fn into_iter(self) -> Self::IntoIter {
        HashMap::from(self).into_iter()
    }
}

#[async_trait]
impl capability::Blobstore for Blobstore {
    #[instrument]
    async fn create_container(&self, name: &str) -> anyhow::Result<()> {
        let mut store = self.0.write().await;
        match store.entry(name.into()) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(RwLock::default());
            }
            hash_map::Entry::Occupied(_) => bail!("container already exists"),
        }
        Ok(())
    }

    #[instrument]
    async fn container_exists(&self, name: &str) -> anyhow::Result<bool> {
        let store = self.0.read().await;
        Ok(store.contains_key(name))
    }

    #[instrument]
    async fn delete_container(&self, name: &str) -> anyhow::Result<()> {
        let mut store = self.0.write().await;
        store.remove(name);
        Ok(())
    }

    #[instrument]
    async fn container_info(
        &self,
        name: &str,
    ) -> anyhow::Result<blobstore::container::ContainerMetadata> {
        let store = self.0.read().await;
        let container = store.get(name).context("container not found")?;
        let Container { created_at, .. } = *container.read().await;
        let created_at = created_at
            .duration_since(UNIX_EPOCH)
            .context("failed to compute duration since Unix epoch")?;
        Ok(blobstore::container::ContainerMetadata {
            name: name.into(),
            created_at: created_at.as_secs(),
        })
    }

    #[instrument]
    async fn get_data(
        &self,
        container: &str,
        name: String,
        range: RangeInclusive<u64>,
    ) -> anyhow::Result<(Box<dyn AsyncRead + Sync + Send + Unpin>, u64)> {
        let store = self.0.read().await;
        let container = store.get(container).context("container not found")?;
        let Container { ref objects, .. } = *container.read().await;
        let Object { data, .. } = objects.get(&name).context("object not found")?;
        let Some(len) = NonZeroUsize::new(data.len()) else {
            return Ok((Box::new(io::empty()), 0))
        };
        let start = (*range.start()).try_into().unwrap_or(usize::MAX);
        let end = (*range.end()).try_into().unwrap_or(usize::MAX);
        let len = len.into();
        let data = data[start.min(len)..=end.min(len - 1)].to_vec();
        let n = data
            .len()
            .try_into()
            .context("length does not fit in `u64`")?;
        Ok((Box::new(Cursor::new(data)), n))
    }

    #[instrument]
    async fn has_object(&self, container: &str, name: String) -> anyhow::Result<bool> {
        let store = self.0.read().await;
        let container = store.get(container).context("container not found")?;
        let Container { ref objects, .. } = *container.read().await;
        Ok(objects.contains_key(&name))
    }

    #[instrument(skip(value))]
    async fn write_data(
        &self,
        container: &str,
        name: String,
        mut value: Box<dyn AsyncRead + Sync + Send + Unpin>,
    ) -> anyhow::Result<()> {
        let store = self.0.read().await;
        let container = store.get(container).context("container not found")?;
        let Container {
            ref mut objects, ..
        } = *container.write().await;
        let buf = objects.entry(name).or_default();
        value
            .read_to_end(&mut buf.data)
            .await
            .context("failed to read value")?;
        Ok(())
    }

    #[instrument]
    async fn delete_objects(&self, container: &str, names: Vec<String>) -> anyhow::Result<()> {
        let store = self.0.read().await;
        let container = store.get(container).context("container not found")?;
        let mut container = container.write().await;
        for name in names {
            container.objects.remove_entry(&name);
        }
        Ok(())
    }

    #[instrument]
    async fn list_objects(
        &self,
        container: &str,
    ) -> anyhow::Result<Box<dyn Stream<Item = anyhow::Result<String>> + Sync + Send + Unpin>> {
        let store = self.0.read().await;
        let container = store.get(container).context("container not found")?;
        let Container { ref objects, .. } = *container.read().await;
        let names: Vec<_> = objects.keys().cloned().collect();
        Ok(Box::new(stream::iter(names.into_iter().map(Ok))))
    }

    #[instrument]
    async fn object_info(
        &self,
        container: &str,
        name: String,
    ) -> anyhow::Result<blobstore::container::ObjectMetadata> {
        let store = self.0.read().await;
        let cont = store.get(container).context("container not found")?;
        let Container { ref objects, .. } = *cont.read().await;
        let Object { created_at, data } = objects.get(&name).context("object not found")?;
        let created_at = created_at
            .duration_since(UNIX_EPOCH)
            .context("failed to compute duration since Unix epoch")?;
        let size = data
            .len()
            .try_into()
            .context("data size does not fit in `u64`")?;
        Ok(blobstore::container::ObjectMetadata {
            name,
            container: container.into(),
            size,
            created_at: created_at.as_secs(),
        })
    }
}
