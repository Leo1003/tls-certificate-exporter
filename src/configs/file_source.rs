use serde::{Deserialize, Serialize};
use std::io::Result as IoResult;
use std::{convert::Infallible, ffi::OsString, path::PathBuf, str::FromStr};
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FileSource {
    Inline {
        #[serde(with = "serde_bytes")]
        content: Vec<u8>,
    },
    Path {
        path: PathBuf,
    },
}

impl FileSource {
    pub async fn load_file(self) -> IoResult<Vec<u8>> {
        match self {
            FileSource::Inline { content } => Ok(content),
            FileSource::Path { path } => {
                let mut file = File::open(path).await?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).await?;
                Ok(buffer)
            }
        }
    }
}

impl FromStr for FileSource {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::Path {
            path: PathBuf::from(s),
        })
    }
}

impl From<PathBuf> for FileSource {
    fn from(path: PathBuf) -> Self {
        Self::Path { path }
    }
}

impl From<OsString> for FileSource {
    fn from(path: OsString) -> Self {
        Self::Path { path: path.into() }
    }
}

impl From<Vec<u8>> for FileSource {
    fn from(content: Vec<u8>) -> Self {
        Self::Inline { content }
    }
}
