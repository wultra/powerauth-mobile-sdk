Pod::Spec.new do |s|
    # General information
    s.cocoapods_version = '>= 1.10'
    s.name              = 'PowerAuth2'
    s.version           = '2.0.0-beta1'
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
        
    # Source files
    s.source = { 
        :git => 'https://github.com/wultra/powerauth-mobile-sdk.git',
        :tag => "#{s.version}",
        :submodules => true
    }
    
    s.ios.deployment_target  = '13.0'
    s.tvos.deployment_target = '13.0'
    
    # XCFramework  build    
    s.prepare_command = <<-CMD
        ./scripts/ios-build-sdk.sh buildSdk --out-dir Build/PowerAuth2 --optional-tvos --include-dsyms
    CMD
    
    # Produced files
    s.vendored_frameworks   = 'Build/PowerAuth2/PowerAuth2.xcframework'
    
end
