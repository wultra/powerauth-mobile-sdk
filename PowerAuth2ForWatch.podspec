Pod::Spec.new do |s|
    # General information
    s.cocoapods_version = '>= 1.10'
    s.name              = 'PowerAuth2ForWatch'
    s.version           = '1.6.5'
    s.summary           = 'PowerAuth Mobile SDK for watchOS'
    s.homepage          = 'https://github.com/wultra/powerauth-mobile-sdk'
    s.social_media_url  = 'https://twitter.com/wultra'
    s.documentation_url = 'https://github.com/wultra/powerauth-mobile-sdk/blob/develop/docs/PowerAuth-SDK-for-watchOS.md'
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
    s.platform        = :watchos, '4.0'
    s.prepare_command = <<-CMD
        ./scripts/ios-build-extensions.sh --out-dir Build/PowerAuth2ForWatch watchos
    CMD
    
    # Produced files
    s.vendored_frameworks   = 'Build/PowerAuth2ForWatch/PowerAuth2ForWatch.xcframework'
    
end