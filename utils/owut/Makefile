#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024 Eric Fahlgren <ericfahlgren@gmail.com>
#

include $(TOPDIR)/rules.mk

PKG_NAME:=owut
PKG_VERSION:=2024.06.17
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=c49480e0a1466187f0cb2d78cd6c3517566e9bf8
PKG_SOURCE_URL:=https://github.com/efahl/$(PKG_NAME).git
PKG_MIRROR_HASH:=780a21a69c6ece8743e1d64b4887cb6d4a5502adc6e081c6866ae831b5aadec3

PKG_MAINTAINER:=Eric Fahlgren <ericfahlgren@gmail.com>
PKG_LICENSE:=GPL-2.0-only

include $(INCLUDE_DIR)/package.mk

define Package/owut
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=owut - an OpenWrt Upgrade Tool
  URL:=http://github.com/efahl/owut
  DEPENDS:=+attendedsysupgrade-common \
    +rpcd-mod-file \
    +ucode +ucode-mod-fs +ucode-mod-ubus \
    +ucode-mod-uci +ucode-mod-uclient +ucode-mod-uloop
  PKGARCH:=all
endef

define Package/owut/description
  The OpenWrt Upgrade Tool (owut) is a command line program that
  checks for new packages, package build breakages, generates
  sysupgrade images containing installed packages and installs
  images.  It is written in ucode for easy end-user customization.

  Documentation is available at https://github.com/efahl/owut
endef

define Package/owut/conffiles
/etc/config/owut
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/owut/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/owut.conf $(1)/etc/config/owut

	$(INSTALL_DIR) $(1)/usr/share/ucode/utils
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/argparse.uc $(1)/usr/share/ucode/utils

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/owut $(1)/usr/bin

	sed -i -e "s/%%VERSION%%/$(PKG_VERSION)-r$(PKG_RELEASE)/" $(1)/usr/bin/owut
endef

$(eval $(call BuildPackage,owut))
