use proc_macro::TokenStream;
use syn::spanned::Spanned;

struct UniffiBuilderMacroInput {
    output_struct: syn::Ident,
    _comma: syn::Token![,],
    defaults: syn::ExprPath,
}

impl syn::parse::Parse for UniffiBuilderMacroInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        Ok(Self {
            output_struct: input.parse()?,
            _comma: input.parse()?,
            defaults: input.parse()?,
        })
    }
}

#[proc_macro_attribute]
#[allow(non_snake_case)]
pub fn UniffiBuilder(args: TokenStream, tokens: TokenStream) -> TokenStream {
    // Get the name of the struct to output to
    let args: UniffiBuilderMacroInput = match syn::parse(args) {
        Ok(args) => args,
        Err(e) => return e.to_compile_error().into(),
    };

    let output_struct_name = args.output_struct;
    let defaults_module = args.defaults;

    // Parse the struct
    let mut tree: syn::ItemStruct = match syn::parse(tokens) {
        Ok(t) => t,
        Err(e) => return e.to_compile_error().into(),
    };

    // Get the name of the struct
    let struct_name = tree.ident.clone();

    // Get the field and type of each fields
    let ((field_names, field_types), field_attributes): (
        (Vec<syn::Ident>, Vec<syn::Type>),
        Vec<Option<syn::Attribute>>,
    ) = tree
        .fields
        .iter()
        .map(|f| {
            let attribute = f
                .attrs
                .iter()
                .find(|a| a.path().is_ident("builder_default"));
            let attribute: Option<syn::Attribute> = attribute.cloned();
            ((f.ident.clone().unwrap(), f.ty.clone()), attribute)
        })
        .collect();

    // Strip the fields from the fields that have custom default
    let (field_names_for_default, field_default): (Vec<syn::Ident>, Vec<syn::Expr>) = tree
        .fields
        .iter()
        .zip(field_attributes.iter())
        .map(|(f, attr)| {
            let ident = f.ident.clone().unwrap();

            let default: syn::Expr = if let Some(attr) = attr {
                if let syn::Meta::NameValue(attr) = attr.meta.clone() {
                    let val = attr.value;
                    syn::parse_quote! { std::sync::Mutex::new({#val}) }
                } else {
                    syn::Expr::Verbatim(
                        syn::Error::new(
                            attr.span(),
                            "The format for the attribute should be #[builder_default = code()]",
                        )
                        .to_compile_error(),
                    )
                }
            } else {
                // Get the uppercased name of the field to get the corresponding default
                let uppercased_ident: syn::Ident =
                    syn::parse_str(&ident.to_string().to_uppercase()).unwrap();
                syn::parse_quote! { std::sync::Mutex::new(#defaults_module::#uppercased_ident) }
            };

            (ident, default)
        })
        .collect();

    // Add mutex to the types
    tree.fields.iter_mut().for_each(|field| {
        let original_type = field.ty.clone();

        // Strip the default attributes
        field
            .attrs
            .retain(|a| !a.path().is_ident("builder_default"));

        field.ty = syn::parse_quote! { std::sync::Mutex<#original_type> };
    });

    quote::quote! {
    #tree

    impl Clone for #struct_name {
        fn clone(&self) -> Self {
            Self {
                #(#field_names: std::sync::Mutex::new(self.#field_names.lock().unwrap().clone()),)*
            }
        }
    }

    impl Default for #struct_name {
        fn default() -> Self {
            Self {
                #(#field_names_for_default: #field_default,)*
            }
        }
    }

    impl #struct_name {
        pub fn new() -> Self {
            Default::default()
        }

        #(
        pub fn #field_names(self: std::sync::Arc<Self>, value: #field_types) -> std::sync::Arc<Self> {
            *self.#field_names.lock().unwrap() = value;
            self
        }
        )*

        pub fn build(self: std::sync::Arc<Self>) -> std::sync::Arc<#output_struct_name> {
            let builder = std::sync::Arc::<#struct_name>::unwrap_or_clone(self);

            #output_struct_name(
                #output_struct_name::get_inner_builder()
                    #(.#field_names(builder.#field_names.into_inner().unwrap()))*
                    .build(),
            )
            .into()
        }
    }
    }
    .into()
}
