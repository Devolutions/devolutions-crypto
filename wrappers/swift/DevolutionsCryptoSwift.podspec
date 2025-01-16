Pod::Spec.new do |s|
    s.name             = 'DevolutionsCryptoSwift'
    s.version          = '0.9.2'
    s.summary          = 'A Swift wrapper around Devolutions Crypto Rust crate'
  
    s.homepage         = 'https://github.com/Devolutions/devolutions-crypto.git'
    s.license          = { :type => 'MIT', :file => './LICENSE-MIT' }
    s.author           = { 'Devolutions Security' => 'security@devolutions.net' }
    s.source           = { 
        :git => 'https://github.com/Devolutions/devolutions-crypto.git', 
        :tag => s.version.to_s,
        :branch => "release/cocoapods-v${version}" 
    }

    s.swift_version = '5.0'
    s.ios.deployment_target = '16.0'

    s.vendored_frameworks = 'DevolutionsCrypto.xcframework'
    s.source_files = [
        'Sources/**/*.{swift}',
        'Tests/**/*.{swift}',
    ]
end