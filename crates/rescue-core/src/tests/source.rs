//! The `Headers` trait, driven by an in-memory source that serves a recorded
//! stretch of mainnet the way Electrum's `blockchain.block.headers` does.

use static_assertions::assert_obj_safe;

use super::chains::{MAINNET_FILES, concat, rows};
use crate::{HEADER_SIZE, HeaderChain, Headers, Network, SourceError};

assert_obj_safe!(Headers);

/// Serves the recorded headers from height 0.
struct Recorded {
    raw: Vec<u8>,
}

impl Recorded {
    fn height(&self) -> usize {
        self.raw.len() / HEADER_SIZE - 1
    }
}

impl Headers for Recorded {
    fn tip(&self) -> Result<u32, SourceError> {
        u32::try_from(self.height()).map_err(|_| SourceError::Malformed)
    }

    fn headers_raw(&self, start: u32, count: u32) -> Result<Vec<u8>, SourceError> {
        if count > 2016 {
            return Err(SourceError::Limit);
        }
        let start = usize::try_from(start).map_err(|_| SourceError::Refused)?;
        if start > self.height() {
            return Err(SourceError::Refused);
        }
        let end = (start + count as usize).min(self.height() + 1);
        Ok(self.raw[start * HEADER_SIZE..end * HEADER_SIZE].to_vec())
    }
}

/// Fetches from a source until the chain reaches its tip.
fn catch_up(source: &dyn Headers, chain: &mut HeaderChain) -> Result<(), SourceError> {
    let tip = source.tip()?;
    while chain.height() < tip {
        let raw = source.headers_raw(chain.height() + 1, 2016)?;
        chain.absorb(&raw).map_err(|_| SourceError::Malformed)?;
    }
    Ok(())
}

#[test]
fn a_source_is_followed_to_its_tip_in_batches() {
    let source = Recorded {
        raw: concat(&rows(MAINNET_FILES[0].0)),
    };
    let mut chain = HeaderChain::new(Network::Mainnet);
    catch_up(&source, &mut chain).unwrap();
    assert_eq!(chain.height(), 4032);
    assert_eq!(chain.to_bytes(), super::chains::early_mainnet().to_bytes());
    // Caught up already: nothing to ask for.
    catch_up(&source, &mut chain).unwrap();
}

#[test]
fn a_source_that_serves_a_forged_header_is_not_believed() {
    let mut raw = concat(&rows(MAINNET_FILES[0].0));
    raw[HEADER_SIZE * 3000 + 76] ^= 1;
    let mut chain = HeaderChain::new(Network::Mainnet);
    assert_eq!(
        catch_up(&Recorded { raw }, &mut chain),
        Err(SourceError::Malformed)
    );
    // The first batch was whole; the second held the forgery and left no trace.
    assert_eq!(chain.height(), 2016);
}

#[test]
fn the_source_errors_name_what_went_wrong() {
    let source = Recorded {
        raw: concat(&rows(MAINNET_FILES[0].0)),
    };
    assert_eq!(source.headers_raw(0, 2017), Err(SourceError::Limit));
    assert_eq!(source.headers_raw(5000, 1), Err(SourceError::Refused));
    assert_eq!(source.headers_raw(4032, 10).unwrap().len(), HEADER_SIZE);
    for error in [
        SourceError::Unavailable,
        SourceError::Malformed,
        SourceError::Limit,
        SourceError::Refused,
    ] {
        assert_ne!(error.to_string(), "");
    }
}
