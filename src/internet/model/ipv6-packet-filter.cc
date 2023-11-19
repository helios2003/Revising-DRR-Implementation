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

#include "ipv6-packet-filter.h"

#include "ipv6-queue-disc-item.h"
#include "tcp-header.h"
#include "udp-header.h"

#include "ns3/enum.h"
#include "ns3/log.h"
#include "ns3/uinteger.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("Ipv6PacketFilter");

NS_OBJECT_ENSURE_REGISTERED(Ipv6PacketFilter);

TypeId
Ipv6PacketFilter::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::Ipv6PacketFilter").SetParent<PacketFilter>().SetGroupName("Internet");
    return tid;
}

Ipv6PacketFilter::Ipv6PacketFilter()
{
    NS_LOG_FUNCTION(this);
}

Ipv6PacketFilter::~Ipv6PacketFilter()
{
    NS_LOG_FUNCTION(this);
}

bool
Ipv6PacketFilter::CheckProtocol(Ptr<QueueDiscItem> item) const
{
    NS_LOG_FUNCTION(this << item);
    return bool(DynamicCast<Ipv6QueueDiscItem>(item));
}

// ------------------------------------------------------------------------- //
NS_OBJECT_ENSURE_REGISTERED(DRRIpv6PacketFilter);

TypeId
DRRIpv6PacketFilter::GetTypeId()
{
    static TypeId tid = TypeId("ns3::DRRIpv6PacketFilter")
                            .SetParent<Ipv6PacketFilter>()
                            .SetGroupName("Internet")
                            .AddConstructor<DRRIpv6PacketFilter>();
    return tid;
}

DRRIpv6PacketFilter::DRRIpv6PacketFilter()
{
    NS_LOG_FUNCTION(this);
}

DRRIpv6PacketFilter::~DRRIpv6PacketFilter()
{
    NS_LOG_FUNCTION(this);
}

int32_t
DRRIpv6PacketFilter::DoClassify(Ptr<QueueDiscItem> item) const
{
    NS_LOG_FUNCTION(this << item);
    Ptr<Ipv6QueueDiscItem> ipv6Item = DynamicCast<Ipv6QueueDiscItem>(item);

    if (!ipv6Item)
    {
        NS_LOG_DEBUG("No match");
        return PacketFilter::PF_NO_MATCH;
    }
    Ipv6Header m_header = ipv6Item->GetHeader();
    Ipv6Address src = m_header.GetSource();
    Ipv6Address dest = m_header.GetDestination();
    uint8_t prot = m_header.GetNextHeader();

    TcpHeader tcpHdr;
    UdpHeader udpHdr;
    uint16_t srcPort = 0;
    uint16_t destPort = 0;

    if (prot == 6) // TCP
    {
        ipv6Item->GetPacket()->PeekHeader(tcpHdr);
        srcPort = tcpHdr.GetSourcePort();
        destPort = tcpHdr.GetDestinationPort();
    }
    else if (prot == 17) // UDP
    {
        ipv6Item->GetPacket()->PeekHeader(udpHdr);
        srcPort = udpHdr.GetSourcePort();
        destPort = udpHdr.GetDestinationPort();
    }
    if (prot != 6 && prot != 17)
    {
        NS_LOG_WARN("Unknown transport protocol, no port number included in hash computation");
    }

    /* serialize the 5-tuple and the perturbation in buf */
    uint8_t buf[37];
    src.Serialize(buf);
    dest.Serialize(buf + 16);
    buf[32] = prot;
    buf[33] = (srcPort >> 8) & 0xff;
    buf[34] = srcPort & 0xff;
    buf[35] = (destPort >> 8) & 0xff;
    buf[36] = destPort & 0xff;
    uint32_t hash = Hash32((char*)buf, 37);

    NS_LOG_DEBUG("Found Ipv6 packet; hash of the five tuple " << hash);

    return hash;
}
} // namespace ns3
