/*
 * Copyright (c) 2016 Universita' degli Studi di Napoli Federico II
 *               2016 University of Washington
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:  Stefano Avallone <stavallo@unina.it>
 *           Tom Henderson <tomhend@u.washington.edu>
 *           Pasquale Imputato <p.imputato@gmail.com>
 */

#include "ipv4-packet-filter.h"
#include "ipv4-queue-disc-item.h"
#include "ns3/enum.h"
#include "ns3/log.h"
#include "tcp-header.h"
#include "udp-header.h"
#include "ns3/uinteger.h"
#include "ns3/packet.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"
#include <typeinfo>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("Ipv4PacketFilter");

NS_OBJECT_ENSURE_REGISTERED(Ipv4PacketFilter);

TypeId
Ipv4PacketFilter::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::Ipv4PacketFilter").SetParent<PacketFilter>().SetGroupName("Internet");
    return tid;
}

Ipv4PacketFilter::Ipv4PacketFilter()
{
    NS_LOG_FUNCTION(this);
}

Ipv4PacketFilter::~Ipv4PacketFilter()
{
    NS_LOG_FUNCTION(this);
}

bool
Ipv4PacketFilter::CheckProtocol(Ptr<QueueDiscItem> item) const
{
    NS_LOG_FUNCTION(this << item);
    return bool(DynamicCast<Ipv4QueueDiscItem>(item));
}

// ------------------------------------------------------------------------- //
NS_OBJECT_ENSURE_REGISTERED (DRRIpv4PacketFilter);

TypeId
DRRIpv4PacketFilter::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::DRRIpv4PacketFilter")
    .SetParent<Ipv4PacketFilter> ()
    .SetGroupName ("Internet")
    .AddConstructor<DRRIpv4PacketFilter> ()
    ;
  return tid;
}

DRRIpv4PacketFilter::DRRIpv4PacketFilter ()
{
  NS_LOG_FUNCTION (this);
}

DRRIpv4PacketFilter::~DRRIpv4PacketFilter ()
{
  NS_LOG_FUNCTION (this);
}

int32_t
DRRIpv4PacketFilter::DoClassify (Ptr<QueueDiscItem> item) const
{
  NS_LOG_FUNCTION (this << item);
  Ptr<Ipv4QueueDiscItem> ipv4Item = DynamicCast<Ipv4QueueDiscItem> (item);

    if (!ipv4Item)
      {
        NS_LOG_DEBUG ("No match");
        return PacketFilter::PF_NO_MATCH;
      }

  Ipv4Header hdr = ipv4Item->GetHeader ();
  Ipv4Address src = hdr.GetSource ();
  Ipv4Address dest = hdr.GetDestination ();
  uint8_t prot = hdr.GetProtocol ();
  uint16_t fragOffset = hdr.GetFragmentOffset ();

  TcpHeader tcpHdr;
  UdpHeader udpHdr;
  uint16_t srcPort = 0;
  uint16_t destPort = 0;

  if (prot == 6 && fragOffset == 0) // TCP
  {
      ipv4Item->GetPacket()->PeekHeader(tcpHdr);
      srcPort = tcpHdr.GetSourcePort();
      destPort = tcpHdr.GetDestinationPort();
  }
  else if (prot == 17 && fragOffset == 0) // UDP
  {
      ipv4Item->GetPacket()->PeekHeader(udpHdr);
      srcPort = udpHdr.GetSourcePort();
      destPort = udpHdr.GetDestinationPort();
  }
  if (prot != 6 && prot != 17)
  {
      NS_LOG_WARN("Unknown transport protocol, no port number included in hash computation");
  }

  /* serialize the 5-tuple and the perturbation in buf */
  uint8_t buf[13];
  src.Serialize(buf);
  dest.Serialize(buf + 4);
  buf[8] = prot;
  buf[9] = (srcPort >> 8) & 0xff;
  buf[10] = srcPort & 0xff;
  buf[11] = (destPort >> 8) & 0xff;
  buf[12] = destPort & 0xff;

  // Linux calculates jhash2 (jenkins hash), we calculate murmur3 because it is
  // already available in ns-3
  uint32_t hash = Hash32((char*)buf, 13);

  NS_LOG_DEBUG("Hash value " << hash);

  return hash;
}


} // namespace ns3
