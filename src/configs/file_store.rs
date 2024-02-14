use std::{
    collections::{hash_map::Entry, HashMap},
    fs::File,
    io::{BufRead, BufReader, Result as IoResult},
    path::{Path, PathBuf},
};
use tokio::{fs::File as AsyncFile, io::AsyncReadExt};

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::RootCertStore;

use super::FileContent;

#[derive(Debug, Default)]
pub struct FileStore {
    data: HashMap<PathBuf, FileData<'static>>,
}

impl FileStore {
    fn read_file_data<P>(
        path: P,
        file_type: FileType,
    ) -> IoResult<FileData<'static>>
    where
        P: AsRef<Path>,
    {
        let file = File::open(path.as_ref())?;
        let mut reader = BufReader::new(file);
        Self::parse_buffer(&mut reader, file_type)
    }

    async fn read_file_data_async<P>(
        path: P,
        file_type: FileType,
    ) -> IoResult<FileData<'static>>
    where
        P: AsRef<Path>,
    {
        let mut file = AsyncFile::open(path.as_ref()).await?;
        let mut data = Vec::new();
        file.read_to_end(&mut data).await?;
        Self::parse_buffer(&mut data.as_slice(), file_type)
    }

    fn parse_buffer(
        buf: &mut dyn BufRead,
        file_type: FileType,
    ) -> IoResult<FileData<'static>> {
        let filedata = match file_type {
            FileType::TrustAnchors => {
                let certs =
                    rustls_pemfile::certs(buf).collect::<IoResult<Vec<_>>>()?;
                let mut store = RootCertStore::empty();
                store.add_parsable_certificates(certs);
                FileData::TrustAnchors(store)
            }
            FileType::Certificates => {
                let certs =
                    rustls_pemfile::certs(buf).collect::<IoResult<Vec<_>>>()?;
                if certs.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "no certificates found",
                    ));
                }
                FileData::Certificates(certs)
            }
            FileType::PrivateKey => {
                let key = rustls_pemfile::private_key(buf)?;
                if let Some(key) = key {
                    FileData::PrivateKey(key)
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "no private key found",
                    ));
                }
            }
            FileType::Data => {
                let mut data = Vec::new();
                buf.read_to_end(&mut data)?;
                FileData::Data(data)
            }
        };

        Ok(filedata)
    }

    pub fn load_file<P>(
        &mut self,
        path: P,
        file_type: FileType,
    ) -> IoResult<&FileData<'static>>
    where
        P: AsRef<Path>,
    {
        let filedata = Self::read_file_data(path.as_ref(), file_type)?;
        self.data.insert(path.as_ref().to_path_buf(), filedata);
        Ok(self.data.get(path.as_ref()).unwrap())
    }

    pub fn get<P>(&self, path: P) -> Option<&FileData<'static>>
    where
        P: AsRef<Path>,
    {
        self.data.get(path.as_ref())
    }

    pub fn fetch<P>(
        &mut self,
        path: P,
        file_type: FileType,
    ) -> IoResult<&FileData<'static>>
    where
        P: AsRef<Path>,
    {
        match self.data.entry(path.as_ref().to_path_buf()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let filedata = Self::read_file_data(path.as_ref(), file_type)?;
                Ok(entry.insert(filedata))
            }
        }
    }

    pub async fn fetch_async<P>(
        &mut self,
        path: P,
        file_type: FileType,
    ) -> IoResult<&FileData<'static>>
    where
        P: AsRef<Path>,
    {
        match self.data.entry(path.as_ref().to_path_buf()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let filedata =
                    Self::read_file_data_async(path.as_ref(), file_type)
                        .await?;
                Ok(entry.insert(filedata))
            }
        }
    }

    pub fn load_file_content(
        &mut self,
        file_content: &FileContent,
        file_type: FileType,
    ) -> IoResult<FileData<'static>> {
        match file_content {
            FileContent::Path { path } => self.fetch(path, file_type).cloned(),
            FileContent::Inline { content } => {
                Self::parse_buffer(&mut content.as_slice(), file_type)
            }
        }
    }

    pub async fn load_file_content_async(
        &mut self,
        file_content: &FileContent,
        file_type: FileType,
    ) -> IoResult<FileData<'static>> {
        match file_content {
            FileContent::Path { path } => {
                self.fetch_async(path, file_type).await.cloned()
            }
            FileContent::Inline { content } => {
                Self::parse_buffer(&mut content.as_slice(), file_type)
            }
        }
    }

    pub fn remove_file<P>(&mut self, path: &P)
    where
        P: AsRef<Path>,
    {
        self.data.remove(path.as_ref());
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

#[derive(Debug)]
pub enum FileData<'a> {
    TrustAnchors(RootCertStore),
    Certificates(Vec<CertificateDer<'a>>),
    PrivateKey(PrivateKeyDer<'a>),
    Data(Vec<u8>),
}

impl<'a> FileData<'a> {
    pub fn clone_trust_anchors(&self) -> Option<RootCertStore> {
        match self {
            FileData::TrustAnchors(store) => Some(store.clone()),
            _ => None,
        }
    }

    pub fn clone_certificates(&self) -> Option<Vec<CertificateDer<'static>>> {
        match self {
            FileData::Certificates(certs) => Some(
                certs.iter().map(|cert| cert.clone().into_owned()).collect(),
            ),
            _ => None,
        }
    }

    pub fn clone_private_key(&self) -> Option<PrivateKeyDer<'static>> {
        match self {
            FileData::PrivateKey(key) => Some(key.clone_key()),
            _ => None,
        }
    }
}

impl Clone for FileData<'_> {
    fn clone(&self) -> Self {
        match self {
            FileData::TrustAnchors(store) => {
                FileData::TrustAnchors(store.clone())
            }
            FileData::Certificates(certs) => FileData::Certificates(
                certs
                    .iter()
                    .cloned()
                    .map(|cert| cert.into_owned())
                    .collect(),
            ),
            FileData::PrivateKey(key) => FileData::PrivateKey(key.clone_key()),
            FileData::Data(data) => FileData::Data(data.clone()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    TrustAnchors,
    Certificates,
    PrivateKey,
    Data,
}
