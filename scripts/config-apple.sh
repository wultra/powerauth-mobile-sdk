# Platform CPU architectures
ARCH_IOS="arm64 arm64e"
ARCH_IOS_SIM="x86_64 arm64"
ARCH_CATALYST="x86_64"
ARCH_TVOS="arm64"
ARCH_TVOS_SIM="x86_64 arm64"
ARCH_WATCHOS="armv7k arm64_32"
ARCH_WATCHOS_SIM="x86_64 i386 arm64"

# Minimum OS version
MIN_VER_IOS="11.0"
MIN_VER_TVOS="11.0"
MIN_VER_CATALYST="10.15"
MIN_VER_WATCHOS="4.0"

# Minimum OS versions when legacy architectures are supported
MIN_LEGACY_VER_IOS="9.0"
MIN_LEGACY_VER_TVOS="9.0"
MIN_LEGACY_VER_WATCHOS="2.0"
ARCH_LEGACY_IOS="armv7 armv7s"
ARCH_LEGACY_SIM="i386"


# -----------------------------------------------------------------------------
# Adjust CPU architectures supported in Xcode, depending on Xcode version.
# -----------------------------------------------------------------------------
ARCH_PATCHED=0
function BUILD_PATCH_ARCHITECTURES
{
    [[ x$ARCH_PATCHED == x1 ]] && return
    ARCH_PATCHED=1
    local xcodever=( $(GET_XCODE_VERSION --split) )
    if (( ${xcodever[0]} == -1 )); then
        FAILURE "Invalid Xcode installation."
    fi
    if (( ${xcodever[0]} < 12 )); then
        FAILURE "Xcode older than 12 is not supported"
    fi
    # Greater and equal than 12.0
    if [[ (${xcodever[0]} == 12 && ${xcodever[1]} < 2) ]]; then
        # 12.0 or 12.1
        WARNING "Building library on older than Xcode 12.2. ARM64 for Catalyst will be omitted."
    else
        # Greater and equal than 12.2
        ARCH_CATALYST+=" arm64"
    fi
    if [[ x$OPT_USE_BITCODE == x1 ]]; then
        if (( ${xcodever[0]} >= 14 )); then
            WARNING "Bitcode is deprecated in Xcode 14+"
        fi
    fi
    if [[ x$OPT_LEGACY_ARCH == x1 ]]; then
        if (( ${xcodever[0]} >= 14 )); then
            FAILURE "Legacy architectures are not supported in Xcode 14+"
        fi
        WARNING "Enabling legacy 32-bit architectures."
        ARCH_IOS+=" $ARCH_LEGACY_IOS"
        ARCH_IOS_SIM+=" $ARCH_LEGACY_SIM"
        WARNING "Changing minimum supported OS versions due to support for 32-bit architectures."
        MIN_VER_IOS=$MIN_LEGACY_VER_IOS
        MIN_VER_TVOS=$MIN_LEGACY_VER_TVOS
        MIN_VER_WATCHOS=$MIN_LEGACY_VER_WATCHOS
    fi
}