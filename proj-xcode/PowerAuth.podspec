Pod::Spec.new do |s|
  s.name                = 'PowerAuth'
  s.version             = '0.12.0'
  s.license             = 'Apache 2.0'
  s.summary             = 'PowerAuth 2.0 Mobile SDK for iOS.'
  s.homepage            = 'http://powerauth.com/'
  s.social_media_url    = 'https://twitter.com/lime_company'
  s.author              = { 'Lime - HighTech Solution s.r.o.' => 'support@lime-company.eu' }
  s.platform            = :ios, '8.0'
  s.source              = { :http => 'https://TODO/PowerAuth_v0_12_0.zip' }
  s.source_files        = 'PowerAuth/*.h'
  s.preserve_paths      = 'PowerAuth/libPowerAuth_v0_12_0.a'
  s.library             = 'PowerAuth_v0_12_0'
  s.xcconfig            = { 'LIBRARY_SEARCH_PATHS' => '"$(PODS_ROOT)/PowerAuth/PowerAuth"' }
end
