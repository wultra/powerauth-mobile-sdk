Pod::Spec.new do |s|
	# General information
	s.name              = 'PowerAuth2'
	s.version           = '%DEPLOY_VERSION%'
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
	
	s.ios.deployment_target  = '8.0'
    s.tvos.deployment_target = '9.0'
    
	# FAT framework build    
	s.prepare_command = <<-CMD
		./scripts/ios-build-libraries.sh --out-dir Library
	CMD
	
	# Produced files
	s.source_files          = 'Library/**/*.{h,m}'
	s.private_header_files  = 'Library/Private/*.h'
	s.vendored_frameworks   = 'Library/*.xcframework'
    s.tvos.exclude_files    = [
        'Library/PA2WC*.{h,m}',
        'Library/Private/PA2WC*.{h,m}',
        'Library/PowerAuthSDK+WatchSupport.m',
        'Library/PowerAuthToken+WatchSupport.{h,m}'
    ]
	s.requires_arc          = true
	s.libraries             = 'c++'
	# Tweaks
	s.pod_target_xcconfig   = {
        'OTHER_LDFLAGS' => '-ObjC',
        'CLANG_WARN_OBJC_IMPLICIT_RETAIN_SELF' => 'NO'
	}
	
end
