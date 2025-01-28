Pod::Spec.new do |s|
    s.name             = 'DevolutionsCryptoSwift'
    s.version          = '2025.1.21'
    s.summary          = 'A Swift wrapper around Devolutions Crypto Rust crate'

    s.homepage         = 'https://github.com/Devolutions/devolutions-crypto.git'
    s.license          = { :type => 'MIT', :file => './LICENSE-MIT' }
    s.author           = { 'Devolutions Security' => 'security@devolutions.net' }
    s.source           = {
        :git => 'https://github.com/Devolutions/devolutions-crypto.git',
        :tag => s.version.to_s
    }

    s.swift_version = '5.0'
    s.ios.deployment_target = '16.0'

    s.vendored_frameworks = 'devolutions-crypto-swift/DevolutionsCrypto.xcframework'
    s.source_files           = 'devolutions-crypto-swift/Sources/DevolutionsCryptoSwift/**/*.swift'

    s.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
    s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
end
