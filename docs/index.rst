Welcome to Pathway Engineering's Autoprovisioning
=================================================
*Setting up switches by outsourcing to software*


Introduction
------------

There is always a large margin for error when setting up Cisco equipment.
Really, there is! Someone may forget to set the boot image. Sometimes the
`config-register` is set to 0x2102 when it should be 0x2101 or vice-versa.
You still have to remember commands that you forgot about because it was
three months ago since you last had to use it. Next thing you know, it's taking
longer than you'd like for getting that gear up on the network.

Autoprovisioning is designed to make the process of setting equipment up faster
and easier. The ability to do it in bulk without actively monitoring activity
is built right in to the core. See the :ref:`CiscoAutoProvision API<cap-api>` page for how
easy it really is.

Contents:

.. toctree::
   :caption: Table of Contents
   :name: mastertoc
   :maxdepth: 3
   :numbered:

   ciscoautoprovision_api
   ciscoupgrade_api
   alerts_api

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

