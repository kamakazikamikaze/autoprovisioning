ciscoupgrade module
=========================

.. module:: ciscoupgrade

ciscoUpgrade API
----------------

.. autoclass:: ciscoUpgrade
   :members: _sendreceive, tftp_setup, cleansoftware, tftp_getimage,
   			 verifyimage, softwareinstall, writemem, sendreload,
   			 tftp_getstartup, blastvlan, tftp_replaceconf

c38xxUpgrade
------------

.. autoclass:: c38xxUpgrade

c45xxUpgrade
------------

.. autoclass:: c45xxUpgrade

ciscoInsecureUpgrade API
------------------------

.. autoclass:: ciscoInsecureUpgrade
   :members: tftp_setup, cleansoftware, tftp_getimage, verifyimage,
             softwareinstall, writemem, erasestartup, sendreload

ciu3850 class
-------------

.. autoclass:: ciu3850

ciu4500 class
-------------

.. autoclass:: ciu4500