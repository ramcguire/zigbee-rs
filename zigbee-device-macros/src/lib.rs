extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro2::TokenStream as TokenStream2;
use quote::format_ident;
use quote::quote;
use syn::Data;
use syn::DeriveInput;
use syn::Error;
use syn::Fields;
use syn::Ident;
use syn::LitInt;
use syn::Path;
use syn::Result;
use syn::Token;
use syn::Type;
use syn::parse::ParseStream;
use syn::parse_macro_input;
use syn::spanned::Spanned;

#[proc_macro_derive(ZigbeeDevice, attributes(zcl, zigbee_device))]
pub fn derive_zigbee_device(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_impl(input)
        .unwrap_or_else(|e| e.into_compile_error())
        .into()
}

#[derive(Default)]
struct ZclAttrs {
    endpoint: Option<(u8, Span)>,
    profile: Option<(u16, Span)>,
    device: Option<(u16, Span)>,
    version: Option<(u8, Span)>,
    is_server: bool,
    client_clusters: Vec<(u16, Span)>,
    manufacturer: Option<(u16, Span)>,
    cluster_override: Option<(u16, Span)>,
}

#[derive(Clone)]
struct EndpointInfo {
    id: u8,
    profile: u16,
    device: u16,
    version: u8,
}

struct ServerInfo {
    field_name: Ident,
    ty: Type,
    endpoint_id: u8,
    profile_id: u16,
    manufacturer_override: Option<u16>,
    cluster_id_override: Option<u16>,
}

struct ClientInfo {
    endpoint_id: u8,
    cluster_id: u16,
}

fn parse_container_attr(attrs: &[syn::Attribute]) -> Result<TokenStream2> {
    for attr in attrs {
        if !attr.path().is_ident("zigbee_device") {
            continue;
        }
        let mut crate_path: Option<Path> = None;
        attr.parse_args_with(|input: ParseStream| -> Result<()> {
            if !input.peek(Token![crate]) {
                return Err(Error::new(input.span(), "expected `crate = <path>`"));
            }
            let _: Token![crate] = input.parse()?;
            let _: Token![=] = input.parse()?;
            crate_path = Some(input.parse()?);
            Ok(())
        })?;
        if let Some(path) = crate_path {
            return Ok(quote! { #path });
        }
    }

    // Auto-discover via proc-macro-crate so renamed dependencies work.
    Ok(
        match proc_macro_crate::crate_name("zigbee-cluster-library") {
            Ok(proc_macro_crate::FoundCrate::Itself) => quote! { crate },
            Ok(proc_macro_crate::FoundCrate::Name(name)) => {
                let ident = Ident::new(&name, Span::call_site());
                quote! { ::#ident }
            }
            Err(_) => quote! { ::zigbee_cluster_library },
        },
    )
}

fn parse_zcl_attrs(attrs: &[syn::Attribute]) -> Result<ZclAttrs> {
    let mut out = ZclAttrs::default();
    let mut errors: Vec<Error> = Vec::new();

    for attr in attrs {
        if !attr.path().is_ident("zcl") {
            continue;
        }
        if let Err(e) = attr.parse_args_with(|input: ParseStream| parse_zcl_args(input, &mut out)) {
            errors.push(e);
        }
    }

    if let Some(e) = combine_errors(errors) {
        return Err(e);
    }
    Ok(out)
}

fn parse_zcl_args(input: ParseStream, out: &mut ZclAttrs) -> Result<()> {
    while !input.is_empty() {
        let ident: Ident = input.parse()?;
        let span = ident.span();

        match ident.to_string().as_str() {
            "server" => {
                out.is_server = true;
            }
            "endpoint" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u8>()?;
                if out.endpoint.is_some() {
                    return Err(Error::new(span, "duplicate `endpoint`"));
                }
                out.endpoint = Some((val, span));
            }
            "profile" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u16>()?;
                if out.profile.is_some() {
                    return Err(Error::new(span, "duplicate `profile`"));
                }
                out.profile = Some((val, span));
            }
            "device" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u16>()?;
                if out.device.is_some() {
                    return Err(Error::new(span, "duplicate `device`"));
                }
                out.device = Some((val, span));
            }
            "version" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u8>()?;
                if out.version.is_some() {
                    return Err(Error::new(span, "duplicate `version`"));
                }
                out.version = Some((val, span));
            }
            "client_cluster" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u16>()?;
                out.client_clusters.push((val, span));
            }
            "manufacturer" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u16>()?;
                if out.manufacturer.is_some() {
                    return Err(Error::new(span, "duplicate `manufacturer`"));
                }
                out.manufacturer = Some((val, span));
            }
            "cluster" => {
                let _: Token![=] = input.parse()?;
                let lit: LitInt = input.parse()?;
                let val = lit.base10_parse::<u16>()?;
                if out.cluster_override.is_some() {
                    return Err(Error::new(span, "duplicate `cluster`"));
                }
                out.cluster_override = Some((val, span));
            }
            other => {
                return Err(Error::new(span, format!("unknown zcl attribute `{other}`")));
            }
        }

        if input.peek(Token![,]) {
            let _: Token![,] = input.parse()?;
        }
    }
    Ok(())
}

fn derive_impl(input: DeriveInput) -> Result<TokenStream2> {
    let struct_name = &input.ident;

    // Named struct only (no enum, union, tuple struct, unit struct).
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(Error::new_spanned(
                    struct_name,
                    "#[derive(ZigbeeDevice)] requires a struct with named fields",
                ));
            }
        },
        _ => {
            return Err(Error::new_spanned(
                struct_name,
                "#[derive(ZigbeeDevice)] can only be applied to structs",
            ));
        }
    };

    // No generics in first cut.
    if !input.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &input.generics,
            "#[derive(ZigbeeDevice)] does not support generic structs",
        ));
    }

    let krate = parse_container_attr(&input.attrs)?;

    let mut errors: Vec<Error> = Vec::new();
    let mut endpoints: Vec<EndpointInfo> = Vec::new();
    let mut servers: Vec<ServerInfo> = Vec::new();
    let mut clients: Vec<ClientInfo> = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_ty = &field.ty;
        let field_span = field.span();

        let zcl = match parse_zcl_attrs(&field.attrs) {
            Ok(a) => a,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        // Rule 9: attributes that only make sense for a server route must not be
        // silently ignored on non-routed fields. `server` is the default for any
        // field with `endpoint = N`.
        let has_endpoint = zcl.endpoint.is_some();
        let is_server = zcl.is_server || has_endpoint;
        if !is_server {
            if let Some((_, s)) = zcl.manufacturer {
                errors.push(Error::new(s, "`manufacturer` requires a server route"));
            }
            if let Some((_, s)) = zcl.cluster_override {
                errors.push(Error::new(s, "`cluster` requires a server route"));
            }
        }

        // Rule 3: server without endpoint.
        if zcl.is_server && zcl.endpoint.is_none() {
            errors.push(Error::new(field_span, "`server` requires `endpoint = N`"));
            continue;
        }

        // client_cluster without endpoint.
        for (_, cs) in &zcl.client_clusters {
            if zcl.endpoint.is_none() {
                errors.push(Error::new(*cs, "`client_cluster` requires `endpoint = N`"));
            }
        }

        let Some((ep_id, ep_span)) = zcl.endpoint else {
            continue; // field not participating in ZCL composition
        };

        // Rule 8: endpoint 0 is ZDO.
        if ep_id == 0 {
            errors.push(Error::new(
                ep_span,
                "endpoint 0 is reserved for ZDO; application endpoints use ids 1–254",
            ));
        }

        // Register or verify endpoint metadata.
        let ep_profile;
        if let Some(existing) = endpoints.iter_mut().find(|e| e.id == ep_id) {
            if let Some((p, s)) = zcl.profile
                && p != existing.profile
            {
                errors.push(Error::new(
                    s,
                    format!(
                        "conflicting `profile` for endpoint {ep_id}: \
                         {p:#06x} vs {:#06x} (first defined above)",
                        existing.profile
                    ),
                ));
            }
            if let Some((d, s)) = zcl.device
                && d != existing.device
            {
                errors.push(Error::new(
                    s,
                    format!(
                        "conflicting `device` for endpoint {ep_id}: \
                         {d:#06x} vs {:#06x} (first defined above)",
                        existing.device
                    ),
                ));
            }
            if let Some((v, s)) = zcl.version
                && v != existing.version
            {
                errors.push(Error::new(
                    s,
                    format!(
                        "conflicting `version` for endpoint {ep_id}: \
                         {v} vs {} (first defined above)",
                        existing.version
                    ),
                ));
            }
            ep_profile = existing.profile;
        } else {
            // Rule 4: first use of endpoint must have profile and device.
            let profile = match zcl.profile {
                Some((p, _)) => p,
                None => {
                    errors.push(Error::new(
                        ep_span,
                        format!("first use of endpoint {ep_id} requires `profile = <u16>`"),
                    ));
                    0
                }
            };
            let device = match zcl.device {
                Some((d, _)) => d,
                None => {
                    errors.push(Error::new(
                        ep_span,
                        format!("first use of endpoint {ep_id} requires `device = <u16>`"),
                    ));
                    0
                }
            };
            let version = zcl.version.map(|(v, _)| v).unwrap_or(0);
            ep_profile = profile;
            endpoints.push(EndpointInfo {
                id: ep_id,
                profile,
                device,
                version,
            });
        }

        // Register server cluster.
        if is_server {
            let mfr = zcl.manufacturer.map(|(m, _)| m);
            let mfr_span = zcl.manufacturer.map(|(_, s)| s);
            let cluster_override = zcl.cluster_override.map(|(c, _)| c);
            let cluster_span = zcl.cluster_override.map(|(_, s)| s);

            let ty_tokens = quote! { #field_ty }.to_string();
            let duplicate = servers.iter().find(|s| {
                let s_ty = &s.ty;
                let same_type_route = s.endpoint_id == ep_id
                    && s.manufacturer_override == mfr
                    && s.cluster_id_override == cluster_override
                    && quote! { #s_ty }.to_string() == ty_tokens;

                let same_literal_route = s.endpoint_id == ep_id
                    && matches!(
                        (s.cluster_id_override, cluster_override),
                        (Some(existing), Some(current)) if existing == current
                    )
                    && matches!(
                        (s.manufacturer_override, mfr),
                        (Some(existing), Some(current)) if existing == current
                    );

                same_type_route || same_literal_route
            });
            if let Some(existing) = duplicate {
                let span = cluster_span.or(mfr_span).unwrap_or(field_span);
                errors.push(Error::new(
                    span,
                    format!(
                        "duplicate server route on endpoint {ep_id}; first route is on field `{}`",
                        existing.field_name
                    ),
                ));
            } else {
                servers.push(ServerInfo {
                    field_name: field_name.clone(),
                    ty: field_ty.clone(),
                    endpoint_id: ep_id,
                    profile_id: ep_profile,
                    manufacturer_override: mfr,
                    cluster_id_override: cluster_override,
                });
            }
        }

        // Register client clusters (output in ZDO descriptor).
        for (cluster_id, cs) in &zcl.client_clusters {
            // Rule 7: duplicate output cluster per endpoint.
            if clients
                .iter()
                .any(|c| c.endpoint_id == ep_id && c.cluster_id == *cluster_id)
            {
                errors.push(Error::new(
                    *cs,
                    format!("duplicate output cluster {cluster_id:#06x} on endpoint {ep_id}"),
                ));
            } else {
                clients.push(ClientInfo {
                    endpoint_id: ep_id,
                    cluster_id: *cluster_id,
                });
            }
        }
    }

    if let Some(e) = combine_errors(errors) {
        return Err(e);
    }

    Ok(generate(
        struct_name,
        &krate,
        &endpoints,
        &servers,
        &clients,
    ))
}

fn generate(
    struct_name: &Ident,
    krate: &TokenStream2,
    endpoints: &[EndpointInfo],
    servers: &[ServerInfo],
    clients: &[ClientInfo],
) -> TokenStream2 {
    // Sort endpoint descriptors by id for stable ZDO responses.
    let mut sorted_eps = endpoints.to_vec();
    sorted_eps.sort_by_key(|e| e.id);

    // Unique prefix derived from struct name for the generated static identifiers.
    // Uppercased struct name suffices — all statics live inside `const _: () = {
    // }`.
    let prefix = struct_name.to_string().to_ascii_uppercase();

    let mut input_statics: Vec<TokenStream2> = Vec::new();
    let mut output_statics: Vec<TokenStream2> = Vec::new();
    let mut descriptor_entries: Vec<TokenStream2> = Vec::new();

    for ep in &sorted_eps {
        let ep_id = ep.id;
        let profile = ep.profile;
        let device = ep.device;
        let version = ep.version;

        let mut input_id_exprs: Vec<TokenStream2> = Vec::new();

        for s in servers.iter().filter(|s| s.endpoint_id == ep_id) {
            if let Some(id_override) = s.cluster_id_override {
                input_id_exprs.push(quote! { #id_override });
            } else {
                let ty = &s.ty;
                input_id_exprs.push(quote! {
                    <#ty as #krate::cluster_server::ClusterServer>::CLUSTER_ID.0
                });
            }
        }
        // Output (client) cluster expressions — deduplicated by id.
        let mut seen_output_ids: Vec<u16> = Vec::new();
        let mut output_exprs: Vec<TokenStream2> = Vec::new();
        for c in clients.iter().filter(|c| c.endpoint_id == ep_id) {
            if !seen_output_ids.contains(&c.cluster_id) {
                seen_output_ids.push(c.cluster_id);
                let id = c.cluster_id;
                output_exprs.push(quote! {
                    #krate::types::ids::ClusterId::new(#id)
                });
            }
        }

        let n_input_raw = input_id_exprs.len();
        let n_output = output_exprs.len();

        let input_static = format_ident!("{prefix}_EP{ep_id}_INPUT");
        let input_raw_const = format_ident!("{prefix}_EP{ep_id}_INPUT_RAW");
        let input_len_const = format_ident!("{prefix}_EP{ep_id}_INPUT_LEN");
        let output_static = format_ident!("{prefix}_EP{ep_id}_OUTPUT");

        input_statics.push(quote! {
            const #input_raw_const: [u16; #n_input_raw] = [
                #(#input_id_exprs),*
            ];
            const #input_len_const: usize = __zcl_count_unique_ids(&#input_raw_const);
            static #input_static: [#krate::types::ids::ClusterId; #input_len_const] =
                __zcl_unique_cluster_ids::<#input_len_const, #n_input_raw>(&#input_raw_const);
        });

        output_statics.push(quote! {
            static #output_static: [#krate::types::ids::ClusterId; #n_output] = [
                #(#output_exprs),*
            ];
        });

        descriptor_entries.push(quote! {
            #krate::cluster_server::EndpointDescriptor {
                endpoint: #ep_id,
                profile_id: #profile,
                device_id: #device,
                device_version: #version,
                input_clusters: &#input_static,
                output_clusters: &#output_static,
            }
        });
    }

    let n_endpoints = sorted_eps.len();
    let endpoints_static = format_ident!("{prefix}_ENDPOINTS");

    let n_routes = servers.len();
    let route_entries = servers.iter().map(|s| {
        let ty = &s.ty;
        let ep_id = s.endpoint_id;
        let cluster_id_u16_expr = if let Some(id) = s.cluster_id_override {
            quote! { #id }
        } else {
            quote! { <#ty as #krate::cluster_server::ClusterServer>::CLUSTER_ID.0 }
        };
        let manufacturer_u16_expr = if let Some(mfr) = s.manufacturer_override {
            quote! { ::core::option::Option::Some(#mfr) }
        } else {
            quote! {
                match <#ty as #krate::cluster_server::ClusterServer>::MANUFACTURER_CODE {
                    ::core::option::Option::Some(code) => ::core::option::Option::Some(code.0),
                    ::core::option::Option::None => ::core::option::Option::None,
                }
            }
        };

        quote! {
            (#ep_id, #cluster_id_u16_expr, #manufacturer_u16_expr)
        }
    });

    // visit_servers calls in source (field) order — determines report priority.
    let visit_calls = servers.iter().map(|s| {
        let field_name = &s.field_name;
        let ty = &s.ty;
        let ep_id = s.endpoint_id;
        let profile_id = s.profile_id;

        let cluster_id_expr = if let Some(id) = s.cluster_id_override {
            quote! { #krate::types::ids::ClusterId::new(#id) }
        } else {
            quote! { <#ty as #krate::cluster_server::ClusterServer>::CLUSTER_ID }
        };

        let manufacturer_expr = if let Some(mfr) = s.manufacturer_override {
            quote! {
                ::core::option::Option::Some(
                    #krate::types::ids::ManufacturerCode::new(#mfr)
                )
            }
        } else {
            quote! { <#ty as #krate::cluster_server::ClusterServer>::MANUFACTURER_CODE }
        };

        quote! {
            visitor.visit(
                #krate::cluster_server::ServerMeta {
                    endpoint: #ep_id,
                    profile_id: #profile_id,
                    cluster: #krate::types::descriptors::ClusterKey::new(
                        #cluster_id_expr,
                        #manufacturer_expr,
                    ),
                },
                &mut self.#field_name,
            );
        }
    });

    quote! {
        const _: () = {
            const fn __zcl_count_unique_ids(ids: &[u16]) -> usize {
                let mut count = 0usize;
                let mut i = 0usize;
                while i < ids.len() {
                    let mut seen = false;
                    let mut j = 0usize;
                    while j < i {
                        if ids[j] == ids[i] {
                            seen = true;
                        }
                        j += 1;
                    }
                    if !seen {
                        count += 1;
                    }
                    i += 1;
                }
                count
            }

            const fn __zcl_unique_cluster_ids<const OUT: usize, const IN: usize>(
                ids: &[u16; IN],
            ) -> [#krate::types::ids::ClusterId; OUT] {
                let mut out = [#krate::types::ids::ClusterId::new(0); OUT];
                let mut count = 0usize;
                let mut i = 0usize;
                while i < IN {
                    let mut seen = false;
                    let mut j = 0usize;
                    while j < i {
                        if ids[j] == ids[i] {
                            seen = true;
                        }
                        j += 1;
                    }
                    if !seen {
                        out[count] = #krate::types::ids::ClusterId::new(ids[i]);
                        count += 1;
                    }
                    i += 1;
                }
                out
            }

            const fn __zcl_same_manufacturer(
                a: ::core::option::Option<u16>,
                b: ::core::option::Option<u16>,
            ) -> bool {
                match (a, b) {
                    (::core::option::Option::Some(a), ::core::option::Option::Some(b)) => a == b,
                    (::core::option::Option::None, ::core::option::Option::None) => true,
                    _ => false,
                }
            }

            const fn __zcl_assert_no_duplicate_routes(
                routes: &[(u8, u16, ::core::option::Option<u16>)],
            ) {
                let mut i = 0usize;
                while i < routes.len() {
                    let mut j = i + 1;
                    while j < routes.len() {
                        if routes[i].0 == routes[j].0
                            && routes[i].1 == routes[j].1
                            && __zcl_same_manufacturer(routes[i].2, routes[j].2)
                        {
                            panic!("duplicate Zigbee server route");
                        }
                        j += 1;
                    }
                    i += 1;
                }
            }

            const __ZCL_SERVER_ROUTES: [(u8, u16, ::core::option::Option<u16>); #n_routes] = [
                #(#route_entries),*
            ];
            const _: () = __zcl_assert_no_duplicate_routes(&__ZCL_SERVER_ROUTES);

            #(#input_statics)*
            #(#output_statics)*

            static #endpoints_static:
                [#krate::cluster_server::EndpointDescriptor; #n_endpoints] = [
                    #(#descriptor_entries),*
                ];

            impl #krate::cluster_server::Device for #struct_name {
                fn endpoints(&self) -> &'static [#krate::cluster_server::EndpointDescriptor] {
                    &#endpoints_static
                }

                fn visit_servers<__ZclV: #krate::cluster_server::DeviceServerVisitor>(
                    &mut self,
                    visitor: &mut __ZclV,
                ) where
                    Self: ::core::marker::Sized,
                {
                    #(#visit_calls)*
                }
            }
        };
    }
}

fn combine_errors(errors: Vec<Error>) -> Option<Error> {
    let mut iter = errors.into_iter();
    let first = iter.next()?;
    Some(iter.fold(first, |mut acc, e| {
        acc.combine(e);
        acc
    }))
}
