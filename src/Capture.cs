// ==================== Capture layer ====================
//
// Types describing the network capture side. Today, dumpcap orchestration + interface
// selection still live inside MainForm — they will migrate here in the Fase 3 rewrite
// (SharpPcap + Npcap live capture, real TCP reassembly). For now this file only owns
// the InterfaceInfo DTO shared between Capture and UI.

namespace WSEngine
{
    class InterfaceInfo
    {
        public int Index;
        public string Device;
        public string Name;
        public override string ToString() { return Index + ": " + Name; }
    }
}
