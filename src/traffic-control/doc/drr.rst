.. include:: replace.txt
.. highlight:: cpp

Deficit Round Robin queue disc
---------------------

Model Description
*****************

Deficit Round Robin (DRR) is a classful queue discipline. It is O(1) fair scheduling algorithm.
Unlike traditional Round Robin scheduling, in DRR
each non-empty queue gets a turn to send packets proportional to its quantum.
The deficit counter, incremented by the quantum,
determines the maximum bytes allowed to be sent from the queue during its turn,
ensuring efficient resource utilization. If a queue is empty, its deficit counter resets to 0.

In the implementation, we set the deficit for the flow which can also be changed if required using
the m_flowsIndices map. Then set the status of the flows as ACTIVE or INACTIVE. Set the quantum value as desired (600 by default).
Enqueue and dequeue the packets as needed and can also peek the top element of the queue without dequeueing.

Attributes
==========

The DRRQueueDisc class holds the following attributes:

* ``ByteLimit:`` The maximum size of the queue in bytes. By default it is 1000 * 1024 bytes.
* ``Flows:`` The number of queues in which packets are put into after being classfied through the hash.

Examples
========

An example of how to configure DRRQueueDisc with custom child queue discs and priomap
is provided by `queue-discs-benchmark.cc` located in ``examples/traffic-control``::

  TrafficControlHelper tch;
  uint handle = tchBottleneck.SetRootQueueDisc("ns3::DRRQueueDisc");
  Config::SetDefault ("ns3::DRRQueueDisc::ByteLimit", UintegerValue (1000 * 1024));
  Config::SetDefault ("ns3::DRRQueueDisc::Flows", UintegerValue (1024));
  tchBottleneck.AddPacketFilter(handle, "ns3::DRRIpv4PacketFilter");

The code snippet sets the DRRQueueDisc as the root queue discipline and sets up the other attributes of the
queue discipline i.e. the ByteLimit and the number of Flows. Finally the packets are classfied into
different flows according to DRRIpv4PacketFilter and DRRIpv6PacketFilter.

Validation
**********

DRRQueueDisc is tested using :cpp:class:`DRRQueueDiscTestSuite` class defined
in ``src/traffic-control/test/drr-queue-disc-test-suite.cc``. The test aims to
check that: i) If the packets are going into different flows and if the size of all the
packets satisfy the byte size of the queue. ii) If the DRR algorithm runs properly on
a single flow iii) If the DRR algorithm runs properly on multiple flows.

The test suite can be run using the following commands:

.. sourcecode:: bash

  $ ./ns3 configure --enable-examples --enable-tests
  $ ./ns3 build
  $ ./test.py -s drr-queue-disc

or

.. sourcecode:: bash

  $ NS_LOG="DRRQueueDisc" ./ns3 run test-runner --command-template="%s --suite=drr-queue-disc --verbose"
