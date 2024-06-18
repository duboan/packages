include $(TOPDIR)/rules.mk

PKG_NAME:=i2csfp
PKG_VERSION:=20240616
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0

PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=ca8e40767e4e14d9e133f73f4689b74baaa0aeaa
PKG_SOURCE_URL:=https://github.com/ericwoud/i2csfp
PKG_MIRROR_HASH:=329d9c72b8e4369bf053c281144637291d3ace04658efe4778a1adda7eac54d6

include $(INCLUDE_DIR)/package.mk

define Package/i2csfp
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=I2C SFP utility
  MAINTAINER:=Daniel Golle <daniel@makrotopia.org>
endef

define Package/i2csfp/description
   A user-space program to access sfp module via i2c.
endef

define Build/Configure
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -Wall \
		-o $(PKG_BUILD_DIR)/i2csfp $(PKG_BUILD_DIR)/i2csfp.c $(TARGET_LDFLAGS)
endef

define Package/i2csfp/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/i2csfp $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,i2csfp))
