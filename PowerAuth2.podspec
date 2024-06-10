Pod::Spec.new do |s|
    # General information
    s.cocoapods_version = '>= 1.10'
    s.name              = 'PowerAuth2'
    s.version           = '1.8.1'
    s.summary           = 'PowerAuth Mobile SDK for iOS'
    s.homepage          = 'https://github.com/wultra/powerauth-mobile-sdk'
    s.social_media_url  = 'https://twitter.com/wultra'
    s.documentation_url = 'https://github.com/wultra/powerauth-mobile-sdk/blob/develop/docs/PowerAuth-SDK-for-iOS.md'
    s.author            = { 
        'Wultra s.r.o.' => 'support@wultra.com'
    }
    s.license = { 
        :type => 'Apache License, Version 2.0', 
        :file => 'LICENSE' 
    }
    s.dependency 'PowerAuthCore', '~> 1.8.1'
        
    # Source files
    s.source = { 
        :git => 'https://github.com/wultra/powerauth-mobile-sdk.git',
        :tag => "#{s.version}",
        :submodules => true
    }
    
    s.ios.deployment_target  = '12.0'
    s.tvos.deployment_target = '12.0'
    
    # XCFramework  build    
    s.prepare_command = <<-CMD
        ./scripts/ios-build-sdk.sh copySdk --out-dir Build/PowerAuth2
    CMD
    
    # Produced files
    s.source_files          = 'Build/PowerAuth2/**/*.{h,m}'
    s.private_header_files  = 'Build/PowerAuth2/Private/*.h'
    s.tvos.exclude_files    = [
        'Build/PowerAuth2/Private/PA2WC*.{h,m}',
        'Build/PowerAuth2/Private/PowerAuthWC*.{h,m}'
    ]
    s.requires_arc          = true
    
    # Tweaks
    s.pod_target_xcconfig   = {
        'OTHER_LDFLAGS' => '-ObjC',
        'CLANG_WARN_OBJC_IMPLICIT_RETAIN_SELF' => 'NO'
    }

end
