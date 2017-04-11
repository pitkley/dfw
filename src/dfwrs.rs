//! DFWRS

use errors::*;
use types::*;

pub fn process(dfw: DFW) -> Result<()> {
    if dfw.container_to_container.is_some() {
        process_container_to_container(dfw)?;
    }

    Ok(())
}

fn process_container_to_container(dfw: DFW) -> Result<()> {
    // TODO: decide if returning an error is the right strategy
    // this only defers the checking of the optional
    let ctc = dfw.container_to_container
        .ok_or(ErrorKind::EmptyKey("container_to_container".to_string()))?;

    // Alternatively:
    //   let ctc = match dfw.container_to_container {
    //       Some(ctc) => ctc,
    //       None => return Ok(()),
    //   };

    Ok(())
}
