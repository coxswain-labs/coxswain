use kube::{Client, api::Api};

/// Returns a namespaced API when `ns` is `Some`, a cluster-wide API when `None`.
pub(crate) fn scoped_api<T>(client: Client, ns: Option<&str>) -> Api<T>
where
    T: kube::Resource<Scope = kube::core::NamespaceResourceScope>,
    T::DynamicType: Default,
{
    match ns {
        Some(ns) => Api::namespaced(client, ns),
        None => Api::all(client),
    }
}
