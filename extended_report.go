package rtcp

import (
	"encoding/binary"
)

// A ExtendedReport (XR) packet provides extended quality feedback for an RTP stream
type ExtendedReport struct {
	// The synchronization source identifier for the originator of this XR packet.
	SSRC uint32 `json:"XRSSRC"`
	// The VoIP Metrics Report Block provides metrics for monitoring voice
	// over IP (VoIP) calls.
	Report *VoIPMetricsReportBlock `json:"VoIPMetricsReport"`
}

type VoIPMetricsReportBlock struct {
	BlockType uint8
	/*Reserved*/
	BlockLength uint16
	//4
	SSRC uint32
	//8
	LossRate     uint8
	DiscardRate  uint8
	BurstDensity uint8
	GapDensity   uint8
	//12
	BurstDuration uint16
	GapDuration   uint16
	//16
	RoundTripDelay uint16
	EndSystemDelay uint16
	//20
	SignalLevel    uint8
	NoiseLevel     uint8
	EchoReturnLoss uint8 //RERL
	GapThreshold   uint8 //Gmin
	//24
	RFactor                      uint8
	ExternalRFactor              uint8
	MeanOpinionScoreListening    uint8 //MOS-LQ
	MeanOpinionScoreConversation uint8 //MOS-CQ
	//28
	RXConfig uint8
	/*Reserved*/
	JitterBufferNominalDelay uint16
	//32
	JitterBufferMaximumDelay         uint16
	JitterBufferAbsoluteMaximumDelay uint16
	//36
}

var _ Packet = (*ExtendedReport)(nil) // assert is a Packet

const (
	xrSSRCOffset   = headerLength
	xrReportOffset = xrSSRCOffset + ssrcLength
)

// Unmarshal decodes the ExtendedReport from binary
func (xr *ExtendedReport) Unmarshal(rawPacket []byte) error {
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V=2|P|reserved |   PT=XR=207   |             length            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                              SSRC                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     BT=7      |   reserved    |       block length = 8        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                       source                         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   loss rate   | discard rate  | burst density |  gap density  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       burst duration          |         gap duration          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |     round trip delay          |       end system delay        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | signal level  |  noise level  |     RERL      |     Gmin      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   R factor    | ext. R factor |    MOS-LQ     |    MOS-CQ     |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |   RX config   |   reserved    |          JB nominal           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |          JB maximum           |          JB abs max           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	if len(rawPacket) < (headerLength + ssrcLength) {
		return errPacketTooShort
	}

	var h Header
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}

	if h.Type != TypeExtendedReport {
		return errWrongType
	}

	if len(rawPacket[xrSSRCOffset:]) != 40 {
		return errPacketTooShort
	}

	xr.SSRC = binary.BigEndian.Uint32(rawPacket[xrSSRCOffset:])

	if len(rawPacket[xrReportOffset:]) != 36 {
		return errPacketTooShort
	}

	xr.Report = new(VoIPMetricsReportBlock)
	xr.Report.BlockType = rawPacket[xrReportOffset]

	if xr.Report.BlockType != 7 {
		return nil
	}

	/*Reserved*/
	xr.Report.BlockLength = binary.BigEndian.Uint16(rawPacket[xrReportOffset+2:])
	xr.Report.SSRC = binary.BigEndian.Uint32(rawPacket[xrReportOffset+4:])
	xr.Report.LossRate = rawPacket[xrReportOffset+8]
	xr.Report.DiscardRate = rawPacket[xrReportOffset+9]
	xr.Report.BurstDensity = rawPacket[xrReportOffset+10]
	xr.Report.GapDensity = rawPacket[xrReportOffset+11]
	xr.Report.BurstDuration = binary.BigEndian.Uint16(rawPacket[xrReportOffset+12:])
	xr.Report.GapDuration = binary.BigEndian.Uint16(rawPacket[xrReportOffset+14:])
	xr.Report.RoundTripDelay = binary.BigEndian.Uint16(rawPacket[xrReportOffset+16:])
	xr.Report.EndSystemDelay = binary.BigEndian.Uint16(rawPacket[xrReportOffset+18:])
	xr.Report.SignalLevel = rawPacket[xrReportOffset+20]
	xr.Report.NoiseLevel = rawPacket[xrReportOffset+21]
	xr.Report.EchoReturnLoss = rawPacket[xrReportOffset+22]
	xr.Report.GapThreshold = rawPacket[xrReportOffset+23]
	xr.Report.RFactor = rawPacket[xrReportOffset+24]
	xr.Report.ExternalRFactor = rawPacket[xrReportOffset+25]
	xr.Report.MeanOpinionScoreListening = rawPacket[xrReportOffset+26]
	xr.Report.MeanOpinionScoreConversation = rawPacket[xrReportOffset+27]
	xr.Report.RXConfig = rawPacket[xrReportOffset+28]
	/*Reserved*/
	xr.Report.JitterBufferNominalDelay = binary.BigEndian.Uint16(rawPacket[xrReportOffset+30:])
	xr.Report.JitterBufferMaximumDelay = binary.BigEndian.Uint16(rawPacket[xrReportOffset+32:])
	xr.Report.JitterBufferAbsoluteMaximumDelay = binary.BigEndian.Uint16(rawPacket[xrReportOffset+34:])

	return nil
}

// Marshal encodes the ExtendedReport in binary
func (xr ExtendedReport) Marshal() ([]byte, error) {
	return nil, nil
}

// DestinationSSRC returns an array of SSRC values that this packet refers to.
func (xr *ExtendedReport) DestinationSSRC() []uint32 {
	return nil
}
