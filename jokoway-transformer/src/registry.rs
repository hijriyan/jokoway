use crate::models::{RequestTransformer, ResponseTransformer};
use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use std::sync::Arc;

// Define the type for a transformer parser factory
pub type RequestTransformerParser = Arc<
    dyn Fn(
            &mut &str,
        ) -> std::result::Result<Box<dyn RequestTransformer>, winnow::error::ContextError>
        + Send
        + Sync,
>;
pub type ResponseTransformerParser = Arc<
    dyn Fn(
            &mut &str,
        )
            -> std::result::Result<Box<dyn ResponseTransformer>, winnow::error::ContextError>
        + Send
        + Sync,
>;

// Global registries
static REQUEST_TRANSFORMER_REGISTRY: Lazy<ArcSwap<Vec<RequestTransformerParser>>> =
    Lazy::new(|| ArcSwap::from_pointee(Vec::new()));
static RESPONSE_TRANSFORMER_REGISTRY: Lazy<ArcSwap<Vec<ResponseTransformerParser>>> =
    Lazy::new(|| ArcSwap::from_pointee(Vec::new()));

fn get_request_registry() -> &'static ArcSwap<Vec<RequestTransformerParser>> {
    &REQUEST_TRANSFORMER_REGISTRY
}

fn get_response_registry() -> &'static ArcSwap<Vec<ResponseTransformerParser>> {
    &RESPONSE_TRANSFORMER_REGISTRY
}

/// Register a custom request transformer parser
pub fn register_request_transformer<F>(parser: F)
where
    F: Fn(
            &mut &str,
        ) -> std::result::Result<Box<dyn RequestTransformer>, winnow::error::ContextError>
        + Send
        + Sync
        + 'static,
{
    let registry = get_request_registry();
    let parser = Arc::new(parser);
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Register a custom response transformer parser
pub fn register_response_transformer<F>(parser: F)
where
    F: Fn(
            &mut &str,
        )
            -> std::result::Result<Box<dyn ResponseTransformer>, winnow::error::ContextError>
        + Send
        + Sync
        + 'static,
{
    let registry = get_response_registry();
    let parser = Arc::new(parser);
    registry.rcu(move |old| {
        let mut new = (**old).clone();
        new.push(parser.clone());
        new
    });
}

/// Try to parse input using registered custom request transformers
pub fn parse_custom_request_transformers(
    input: &mut &str,
) -> std::result::Result<Box<dyn RequestTransformer>, winnow::error::ContextError> {
    let registry = get_request_registry();
    let parsers = registry.load();

    let mut last_err = None;
    for parser in parsers.iter() {
        let mut temp_input = *input;
        match parser(&mut temp_input) {
            Ok(transformer) => {
                *input = temp_input;
                return Ok(transformer);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(err) = last_err {
        Err(err)
    } else {
        Err(winnow::error::ContextError::default())
    }
}

/// Try to parse input using registered custom response transformers
pub fn parse_custom_response_transformers(
    input: &mut &str,
) -> std::result::Result<Box<dyn ResponseTransformer>, winnow::error::ContextError> {
    let registry = get_response_registry();
    let parsers = registry.load();

    let mut last_err = None;
    for parser in parsers.iter() {
        let mut temp_input = *input;
        match parser(&mut temp_input) {
            Ok(transformer) => {
                *input = temp_input;
                return Ok(transformer);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    if let Some(err) = last_err {
        Err(err)
    } else {
        Err(winnow::error::ContextError::default())
    }
}
