Pod::Spec.new do |s|
    # General information
    s.cocoapods_version = '>= 1.10'
    s.name              = 'PowerAuth2ForExtensions'
    s.version           = '1.7.5'
    s.summary           = 'PowerAuth Mobile SDK for iOS and tvOS App Extensions'
    s.homepage          = 'https://github.com/wultra/powerauth-mobile-sdk'
    s.social_media_url  = 'https://twitter.com/wultra'
    s.documentation_url = 'https://github.com/wultra/powerauth-mobile-sdk/blob/develop/docs/PowerAuth-SDK-for-iOS-Extensions.md'
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
        # submodules => false is enough, but we're using the same git repo as PA2 and cocoapods 
        # doesn't like when the same repo is cloned without and then with sumbodules...
        :submodules => true
    }
    
    # Library build
    s.ios.deployment_target  = '11.0'
    s.tvos.deployment_target = '11.0'
    
    s.prepare_command = <<-CMD
        ./scripts/ios-build-extensions.sh --out-dir Build/PowerAuth2ForExtensions extensions
    CMD
    
    # Produced files
    s.vendored_frameworks   = 'Build/PowerAuth2ForExtensions/PowerAuth2ForExtensions.xcframework'
    
end