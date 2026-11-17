//! ADPP participates in the same catalog as native provider implementations.
use aster_acme_dns::{
    ProviderError,
    backend::{
        ADPP_BACKEND_ID, BackendConfig, BackendDescriptor, BackendImplementation,
        BackendRegistration, DnsBackend, configuration_error,
    },
};
use std::{sync::Arc, time::Duration};

#[linkme::distributed_slice(aster_acme_dns::backend::BACKENDS)]
static REGISTRATION: BackendRegistration = BackendRegistration {
    create: || Arc::new(AdppBackend),
};

struct AdppBackend;
impl DnsBackend for AdppBackend {
    fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            id: ADPP_BACKEND_ID,
            label: "External ADPP executable",
            config_version: 1,
            executable: true,
            mutation_model: aster_acme_dns::backend::MutationModel::ExternalProtocol,
            fields: &[],
        }
    }
    fn validate(&self, config: &BackendConfig) -> Result<(), ProviderError> {
        if config.version != 1 {
            return Err(configuration_error(
                "unsupported ADPP backend configuration version",
            ));
        }
        if !config.executable.is_absolute() || config.args.iter().any(|arg| arg.contains('\0')) {
            return Err(configuration_error(
                "ADPP requires an absolute executable and valid arguments",
            ));
        }
        Ok(())
    }
    fn binding(&self, config: &BackendConfig) -> Result<String, ProviderError> {
        serde_json::to_string(&(config.executable.as_os_str(), &config.args))
            .map_err(|_| configuration_error("invalid ADPP executable identity"))
    }
    fn create(&self, config: &BackendConfig) -> Result<BackendImplementation, ProviderError> {
        self.validate(config)?;
        Ok(BackendImplementation::External(Arc::new(
            crate::AdppProvider::new(crate::Executable {
                program: config.executable.clone(),
                args: config.args.iter().map(Into::into).collect(),
                timeout: Duration::from_secs(300),
            }),
        )))
    }
}
