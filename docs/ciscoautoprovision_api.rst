ciscoautoprovision module
=========================

.. module:: ciscoautoprovision

.. autofunction:: generate_config

.. _cap-api:

CiscoAutoProvision API
----------------------

.. autoclass:: CiscoAutoProvision
   :members: run, autoupgrade, _setuplogger, ping, _parseconfig, search, _k9,
   			 _upgradefirst, _get_new_name, _get_serial, _ssh_opensession,
   			 _prepupgrade, _tftp_replace, _tftp_replace, _tftp_startup,
   			 _startupcfg, _gen_rsa, _lock, _unlock, _wait, sendalerts

Helper class
------------

.. autoclass:: Helper
   :members: tftp_putconf, tftp_getconf

CapTest class
-------------

.. autoclass:: CapTest