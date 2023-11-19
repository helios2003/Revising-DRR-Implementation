/*
 * Copyright (c) 2017-2023 NITK Surathkal
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
 * Authors: Akhil Udathu <akhilu077@gmail.com>
 *          Kaushik S Kalmady <kaushikskalmady@gmail.com>
 *          Vilas M <vilasnitk19@gmail.com>
 * Ported by:
 *          Ankit Dash <ankitdash2019@gmail.com>
 *          Vedika Gadia <vedikagadia02@gmail.com>
 *          Samhita R <sammyrengs73@gmail.com>
 *          Bishakh Dutta <telbdzone@gmail.com>
 */

#include "drr-queue-disc.h"

#include "ns3/ipv4-packet-filter.h"
#include "ns3/log.h"
#include "ns3/net-device-queue-interface.h"
#include "ns3/queue.h"
#include "ns3/string.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("DRRQueueDisc");

NS_OBJECT_ENSURE_REGISTERED(DRRFlow);

TypeId
DRRFlow::GetTypeId()
{
    static TypeId tid = TypeId("ns3::DRRFlow")
                            .SetParent<QueueDiscClass>()
                            .SetGroupName("TrafficControl")
                            .AddConstructor<DRRFlow>();
    return tid;
}

DRRFlow::DRRFlow()
    : m_deficit(0),
      m_status(INACTIVE)
{
    NS_LOG_FUNCTION(this);
}

DRRFlow::~DRRFlow()
{
    NS_LOG_FUNCTION(this);
}

void
DRRFlow::SetDeficit(uint32_t deficit)
{
    NS_LOG_FUNCTION(this << deficit);
    m_deficit = deficit;
}

int32_t
DRRFlow::GetDeficit() const
{
    NS_LOG_FUNCTION(this);
    return m_deficit;
}

void
DRRFlow::IncreaseDeficit(int32_t deficit)
{
    NS_LOG_FUNCTION(this << deficit);
    m_deficit += deficit;
}

void
DRRFlow::SetStatus(FlowStatus status)
{
    NS_LOG_FUNCTION(this);
    m_status = status;
}

DRRFlow::FlowStatus
DRRFlow::GetStatus() const
{
    NS_LOG_FUNCTION(this);
    return m_status;
}

NS_OBJECT_ENSURE_REGISTERED(DRRQueueDisc);

TypeId
DRRQueueDisc::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::DRRQueueDisc")
            .SetParent<QueueDisc>()
            .SetGroupName("TrafficControl")
            .AddConstructor<DRRQueueDisc>()
            .AddAttribute("ByteLimit",
                          "The hard limit on the real queue size, measured in bytes",
                          UintegerValue(1000 * 1024),
                          MakeUintegerAccessor(&DRRQueueDisc::m_limit),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("Flows",
                          "The number of queues into which the incoming packets are classified",
                          UintegerValue(1024),
                          MakeUintegerAccessor(&DRRQueueDisc::m_flows),
                          MakeUintegerChecker<uint32_t>());
    return tid;
}

DRRQueueDisc::DRRQueueDisc()
    : m_quantum(0)
{
    NS_LOG_FUNCTION(this);
}

DRRQueueDisc::~DRRQueueDisc()
{
    NS_LOG_FUNCTION(this);
}

void
DRRQueueDisc::SetQuantum(uint32_t quantum)
{
    NS_LOG_FUNCTION(this << quantum);
    m_quantum = quantum;
}

uint32_t
DRRQueueDisc::GetQuantum() const
{
    return m_quantum;
}

bool
DRRQueueDisc::DoEnqueue(Ptr<QueueDiscItem> item)
{
    NS_LOG_FUNCTION(this << item);

    int32_t ret = Classify(item);
    uint32_t h;

    if (ret == PacketFilter::PF_NO_MATCH)
    {
        NS_LOG_WARN("No filter has been able to classify this packet.");
        h = m_flows; // place all unfiltered packets into a separate flow queue
    }

    else
    {
        h = ret % m_flows;
    }

    Ptr<DRRFlow> flow;
    if (m_flowsIndices.find(h) == m_flowsIndices.end())
    {
        NS_LOG_DEBUG("Creating a new flow queue with index " << h);
        flow = m_flowFactory.Create<DRRFlow>();
        Ptr<QueueDisc> qd = m_queueDiscFactory.Create<QueueDisc>();
        qd->Initialize();
        flow->SetQueueDisc(qd);
        AddQueueDiscClass(flow);

        m_flowsIndices[h] = GetNQueueDiscClasses() - 1;
    }
    else
    {
        flow = StaticCast<DRRFlow>(GetQueueDiscClass(m_flowsIndices[h]));
    }

    flow->GetQueueDisc()->Enqueue(item);

    NS_LOG_DEBUG("Packet enqueued into flow " << h << "; flow index " << m_flowsIndices[h]);

    if (flow->GetStatus() == DRRFlow::INACTIVE)
    {
        NS_LOG_DEBUG("Setting flow as ACTIVE");
        flow->SetStatus(DRRFlow::ACTIVE);
        m_flowList.push_back(flow);
    }

    while (GetNBytes() > m_limit)
    {
        DRRDrop();
    }

    return true;
}

Ptr<QueueDiscItem>
DRRQueueDisc::DoDequeue()
{
    NS_LOG_FUNCTION(this);

    Ptr<DRRFlow> flow;
    Ptr<QueueDiscItem> item;

    if (m_flowList.empty())
    {
        NS_LOG_DEBUG("No active flows found");
        return nullptr;
    }

    do
    {
        if (!m_flowList.empty()) // unnecessary ?
        {
            flow = m_flowList.front();
            m_flowList.pop_front();
            flow->IncreaseDeficit(m_quantum);
            Ptr<const QueueDiscItem> t_item = flow->GetQueueDisc()->Peek();

            if ((uint32_t)flow->GetDeficit() >= t_item->GetSize())
            {
                item = flow->GetQueueDisc()->Dequeue();
                flow->IncreaseDeficit(-item->GetSize());
                NS_LOG_DEBUG("Dequeued packet " << item->GetPacket());

                if (flow->GetQueueDisc()->GetNPackets() == 0)
                {
                    NS_LOG_DEBUG("Empty Flow, Setting it to INACTIVE");
                    flow->SetDeficit(0);
                    flow->SetStatus(DRRFlow::INACTIVE);
                }

                else
                {
                    NS_LOG_DEBUG("Flow still active, pushing back to active list");
                    m_flowList.push_back(flow);
                }

                return item;
            } // End if(flow->GetDeficit ...)

            else
            {
                NS_LOG_DEBUG("Packet size greater than deficit, pushing flow back to end of list");
                m_flowList.push_back(flow);
                item = nullptr;
            }
        }
        else
        {
            NS_LOG_DEBUG("No active flows found");
            return nullptr;
        }
    } while (!item);

    return nullptr; // never reached
}

Ptr<const QueueDiscItem>
DRRQueueDisc::DoPeek()
{
    NS_LOG_FUNCTION(this);

    Ptr<DRRFlow> flow;

    if (!m_flowList.empty())
    {
        flow = m_flowList.front();
    }
    else
    {
        return nullptr;
    }

    return flow->GetQueueDisc()->Peek();
}

bool
DRRQueueDisc::CheckConfig()
{
    NS_LOG_FUNCTION(this);
    if (GetNQueueDiscClasses() > 0)
    {
        NS_LOG_ERROR("DRRQueueDisc cannot have classes");
        return false;
    }

    if (GetNPacketFilters() == 0)
    {
        // Ptr<DRRIpv4PacketFilter> ipv4Filter = CreateObject<DRRIpv4PacketFilter> ();
        // AddPacketFilter (ipv4Filter);
        NS_LOG_ERROR("DRRQueueDisc needs at least a packet filter");
        return false;
    }

    if (GetNInternalQueues() > 0)
    {
        NS_LOG_ERROR("DRRQueueDisc cannot have internal queues");
        return false;
    }

    return true;
}

void
DRRQueueDisc::InitializeParams()
{
    NS_LOG_FUNCTION(this);

    // we are at initialization time. If the user has not set a quantum value,
    // set the quantum to the MTU of the device
    if (!m_quantum)
    {
        // Ptr<NetDevice> device = GetNetDevice ();
        // NS_ASSERT_MSG (device, "Device not set for the queue disc");
        // m_quantum = device->GetMtu ();
        m_quantum = 600;
        NS_LOG_DEBUG("Setting the quantum to: " << m_quantum);
    }

    m_flowFactory.SetTypeId("ns3::DRRFlow");

    m_queueDiscFactory.SetTypeId("ns3::CoDelQueueDisc");

    // m_queueDiscFactory.Set ("Mode", EnumValue (QueueBase::QUEUE_MODE_BYTES));
    // m_queueDiscFactory.Set ("MaxPackets", UintegerValue (m_limit + 1));
    //  m_queueDiscFactory.Set ("Interval", StringValue (m_interval));
    // m_queueDiscFactory.Set ("Target", StringValue (m_target));
}

uint32_t
DRRQueueDisc::DRRDrop()
{
    NS_LOG_FUNCTION(this);

    uint32_t maxBacklog = 0;
    uint32_t index = 0;
    Ptr<QueueDisc> qd;

    /* Queue is full! Find the fat flow and drop one packet from it */
    for (uint32_t i = 0; i < GetNQueueDiscClasses(); i++)
    {
        qd = GetQueueDiscClass(i)->GetQueueDisc();
        uint32_t bytes = qd->GetNBytes();
        if (bytes > maxBacklog)
        {
            maxBacklog = bytes;
            index = i;
        }
    }

    /* Now we drop one packet from the fat flow */
    qd = GetQueueDiscClass(index)->GetQueueDisc();
    Ptr<QueueDiscItem> item;
    item = qd->GetInternalQueue(0)->Dequeue();
    DropAfterDequeue(item, OVERLIMIT_DROP);

    return index;
}

} // namespace ns3
