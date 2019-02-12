Pod::Spec.new do |s|
	# General information
	s.name              = 'PowerAuth2'
	s.version           = '0.20.0'
	s.summary           = 'PowerAuth Mobile SDK for iOS'
	s.homepage          = 'https://github.com/wultra/powerauth-mobile-sdk'
	s.social_media_url  = 'https://twitter.com/wultra'
	s.documentation_url = 'https://github.com/wultra/powerauth-mobile-sdk/docs/PowerAuth-SDK-for-iOS.md'
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
	
	# FAT framework build
	s.platform        = :ios, '8.0'
	s.prepare_command = <<-CMD
		./scripts/ios-build-libraries.sh release --out-dir Library
	CMD
	
	# Produced files
	s.source_files          = 'Library/**/*.{h,m}'
	s.private_header_files  = 'Library/Private/*.h'
	s.vendored_libraries    = 'Library/libPowerAuthCore.a'
	s.requires_arc          = true
	s.libraries             = 'c++'
	# Tweaks
	s.pod_target_xcconfig   = {
		'OTHER_LDFLAGS' => '-ObjC',
		'CLANG_WARN_OBJC_IMPLICIT_RETAIN_SELF' => 'NO'
	}
	
end
