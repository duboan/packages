#
# Copyright (C) 2006-2015 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Package/python3-dev
$(call Package/python3/Default)
  TITLE:=Python $(PYTHON3_VERSION) development files
  DEPENDS:=+python3
endef

define Py3Package/python3-dev/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/python$(PYTHON3_VERSION)-config $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/bin/python*config $(1)/usr/bin
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libpython$(PYTHON3_VERSION).so* $(1)/usr/lib
endef

$(eval $(call Py3BasePackage,python3-dev, \
    /usr/lib/python$(PYTHON_VERSION)/config-$(PYTHON_VERSION) \
    /usr/include/python$(PYTHON_VERSION) \
    /usr/lib/pkgconfig \
	, \
	DO_NOT_ADD_TO_PACKAGE_DEPENDS \
))
