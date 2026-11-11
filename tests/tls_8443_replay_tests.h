#pragma once

namespace {

void TestTls8443PacketSequence() {
    struct Sample {
        uint64_t id;
        uint8_t layer;
        bool inbound;
        std::string_view hex;
        pmkext::Verdict expected;
    };
    // Полная последовательность из захвата: transport, SYN, SYN+ACK, ACK
    // и два последовательных TCP-сегмента одного ClientHello.
    const Sample samples[]{
        {1173, 4, false, "", pmkext::Verdict::Accept},
        {1174, 3, false,
         "4500003c9ea1400080064dea0add5406b99df5afddaf20fb0e63040d00000000a002ffff5f77000002040564010303080402080a007ac91200000000",
         pmkext::Verdict::Accept},
        {1183, 3, true,
         "4500003c0000400032063a8cb99df5af0add540620fbddaf015704c00e63040ea012fe886e050000020405b40402080a1502d76c007ac9120103030a",
         pmkext::Verdict::Accept},
        {1184, 3, false,
         "450000349ea2400080064df10add5406b99df5afddaf20fb0e63040e015704c1801000ff9a2000000101080a007ac9501502d76c",
         pmkext::Verdict::Accept},
        {1186, 3, false,
         "4500058c9ea34000800648980add5406b99df5afddaf20fb0e63040e015704c1801000ff462f00000101080a007ac9511502d76c"
         "16030106c3010006bf03032e9e78797798e5741d062a452e1c6e3bd61a0b5fb8fff05940644c3e44cb4a682029d00396b11f24994372b3de1b8c57843576fae74a77ede908ed291d167e23e1"
         "0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f003501000656dada000044cd0005000302683200170000fe0d00ba0000010001c20020"
         "7bf9eeaf38fe4c7fc44e0e66d6be4d8b6bb59aaa386c23b71fcf27756b02e6660090d6e56ab16fcbbfef7e5ac0799c2f99bb20a0b9efa0b269418d2a4c36ce481eacb12681297d3b9fc664fb01832ed0b575d24ac84da708abff5878cc21a482d41f456fb4ca5b917fb892d531063621bdde10fd95a44c96d8164056f822f58136ba9e5b681ad6bdb27af2fcb3bdf2a6a82228bfcff74a79dcabf1712ea9624bb8851facec133080a80311b0d75435fe0d5a"
         "002b0007067a7a0304030300120000000500050100000000001b0003020002003304ef04eddada00010011ec04c0"
         "6287b1a9e5942887a12860931c68b3383246bbb1100af0b7e3887fe56261252871b9d07ce06155cb54bac4f9003784843574032666470c042ce64c5af990241fe2450f1618daf33a4c8bab45849a89462cec5b46d8980aee604b7817ac15fcbb24498fe294ad4ce1bb06466f133646d406a35b6c6fd30747d4e224734446fc12adc065c5aa62be74f9644e361c1f188993c2b5bc1c9bb85cb92a7479d598a51ad9b89d121e9ed69c0e81cde06596d2e2bc82216f2bfaca9455cdc8b690a49017b9a92bab514724939bb648bdece91c02a5c0095822de863188a3766ac976290a592a648adb808f21b88aa13194d3cbc2449072f397c6ceec5f8786a27fc666ad64c8b23351c8e737caac4de81092fb1706d6b7c2e4a645861525a075ab7ab7291a58289a64cf5413529c891ac4063b0e1a05e5d1b22b386499eb386da4caea2c52814648bdd9119d248468e49800068811338640177f4b765ccd26caf55145d42520a942955a30bb4e75c3cc753932927917807ad44972f80123796489f5ab1820f80498e1825f456be3d012f4fab84a2308b6d692cbc4b01cb5127f343b12c42982a5c10a31b420ab026dc19e61a4ba427b1e823abd9784538dd463f7cc08968679ed55b082d843bf31bc30ac23aba7476f431be615b3c25297651b2d55e153f4488bde917d63b1bd296482d8daa80406c6d0da6b3050b75fbb2434f0902d7247f1a48e5448315921764ee742969c9c08d9204e093826b056652a34b6b00579b4ad0485c46999aa02c41479a99cd8987632459bbcc25c3b20a275667be4e97fb4e7aa582c9a5696b35b001d5af29532d1c79b3ac09b9597a8fc59ffb82083d2998867a96ee90851347ec30a7901927e2075c694458d020c6bceea21f5a86bdfe017651652506186f126bd5e368debc245210ca10e592f5f759652c9b12fd90bdc95cab87c2e98d3c148e75717e02c3c6357d4dc34368b82fea101f930854cdc75ada54ee0eaa9c6052f6ae5358dec02748099e3896ab86c6376e733a52ab2f25383b265a25d6088aa69979236409ccca417738d8ba4adf00859a292c0203c7914e6a164c4984bab5de59993cbea99e9ab9eac465e6c81bef7c0c48921984daa5c98581390a58164467555672e438267fee106d633c332dcca0e9193693286e4a57f9ad07237a48ccd791024baca717c1d387077ab2b9e89a4671c8b4de37945a7ea7c01eacd6e43a6bac9cbf6ac10c62abd80b56ff85ca64623315587a9da8ca48c356b47e65352ea0b2beab7f2213a97c20a4aac9172ec8597773fa1b4b69b4b2d3f68294f194a4c9c716ae98d07a15d6ae9bae45555f0c8695fe2a16dfa05ab2a7ac190669f43a7b421bf062773d96794279a59e750bb4bb6c7c45a530cd3014175cfdc2886640c",
         pmkext::Verdict::Accept},
        {1187, 3, false,
         "450001a49ea4400080064c7f0add5406b99df5afddaf20fb0e630966015704c1801800ff8e2b00000101080a007ac9511502d76c"
         "50fe6a26d022055f9062428542dcaa61fa588b3fba2feb482b13d60c9746161917ae63919482039a234c5e7da414aba74ae4b45839bcaec6558534b433541969abd655d0927d5ddacc582375aa143f01f83617790e6a21495fca7b51806302a3988e85c43b56803f1c70aa01c63f8cca82e809dad9b3aa85ba3b10156cb462db1cb6fcf0318bc0b78e319bfb7a71f0aa61ba070f647b109df8c9150815e4a48acc077295d8f7df76f84f321f0c4c5ba66d606df525b00badeaef2706c88d9ae7789e3fccc658cf447ce58a9115733ba059300213ff9d10001d00203103537e357f59fa581db0c05d7db9c76b9d2ca3ace9291aca947babfd16842c000b00020100000000170015000012636c617564652d6e2d636f6465782e636f6d000d001a00187a7a09040905090604030804040105030805050108060601002d00020101ff010001000010000e000c02683208687474702f312e3100230000000a000c000adada11ec001d001700187a7a000100",
         pmkext::Verdict::PermanentAccept},
    };
    const auto decode = [](std::string_view hex) {
        const auto digit = [](char ch) -> uint8_t {
            if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
            Check(ch >= 'a' && ch <= 'f', "invalid hex digit in TLS capture");
            return static_cast<uint8_t>(ch - 'a' + 10);
        };
        Check(hex.size() % 2 == 0, "odd hex length in TLS capture");
        std::vector<uint8_t> bytes;
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2)
            bytes.push_back(static_cast<uint8_t>((digit(hex[i]) << 4) | digit(hex[i + 1])));
        return bytes;
    };

    FlowStore& flows = FlowStore::Instance();
    const bool wasEnabled = flows.enabled();
    flows.Enable(true);
    flows.Reset();
    DriverVerdictSession session;
    captureSession = &session;
    sentVerdicts.clear();
    RuleStore rules;
    Rule allow;
    allow.scope = RuleScope::Global;
    allow.conds = CondNone;
    allow.action = RuleAction::Allow;
    rules.Add(allow);
    auto ingest = IngestTestAccess::Create();
    ingest->Attach(&rules, nullptr);
    ingest->BeginDriverSession(session.Begin());

    auto event = IngestOptimization::Event<pmkext::ConnectionFixedV4>(8443);
    const IpAddr local = Ip(L"10.221.84.6");
    const IpAddr remote = Ip(L"185.157.245.175");
    std::copy_n(local.b, sizeof(event.local_ip), event.local_ip);
    std::copy_n(remote.b, sizeof(event.remote_ip), event.remote_ip);
    event.local_port = 56751;
    event.interface_index = 12;
    const FlowKey key = MakeFlowKey(Proto::Tcp, local, remote, 56751, 8443);
    const auto label = [&]() {
        FlowStore::DisplayView view;
        flows.TakeDisplay(view);
        for (const auto& process : view.processes) {
            if (process.group != TrafficGroupKey::Host(static_cast<DWORD>(event.process_id)))
                continue;
            for (const auto& connection : process.connections)
                if (connection.key == key && connection.tlsDomainLabel)
                    return *connection.tlsDomainLabel;
        }
        return std::wstring();
    };

    for (const auto& sample : samples) {
        const auto bytes = decode(sample.hex);
        event.external_connection_id = sample.id;
        event.payload_layer = sample.layer;
        event.direction = sample.inbound ? 1 : 0;
        const size_t before = sentVerdicts.size();
        IngestOptimization::Receive(*ingest, event, bytes);
        // Проверка останавливает воспроизведение сразу при преждевременном
        // PermanentAccept: настоящий драйвер больше не прислал бы пакеты.
        Check(sentVerdicts.size() == before + 1 &&
                  sentVerdicts.back() == std::pair{sample.id, sample.expected},
              "captured TLS 8443 sequence received an unexpected verdict");
        if (sample.id != 1187)
            Check(label().empty(), "captured TLS 8443 published SNI before ClientHello completed");
    }
    Check(label() == L"[claude-n-codex.com]", "captured TLS 8443 sequence lost its SNI domain");
    Check(ingest->waiting() == 0 && ingest->calls() == ingest->answered(),
          "captured TLS 8443 sequence lost a driver obligation");
    ingest->EndDriverSession(session.End());
    captureSession = nullptr;
    flows.Reset();
    flows.Enable(wasEnabled);
}

} // анонимное пространство имён
