
module TrafficAnalysis;

export {
    redef enum Notice::Type += {
        HighRateConnection,
        UnusualDataUpload,
        PortScanActivity,
        BeaconBehavior,
        DNSTunnelSuspect,
        ICMPLargePayload,
        SuspiciousPortAccess,
    };

    const high_rate_threshold: count = 20 &redef;
    const rate_window: interval = 60sec &redef;
    const upload_ratio_threshold: double = 0.85 &redef;
    const upload_min_bytes: count = 50000 &redef;
    const icmp_large_threshold: count = 200 &redef;
    const beacon_jitter_threshold: double = 0.15 &redef;

    const suspicious_ports: set[port] = {
        4444/tcp, 1337/tcp, 31337/tcp, 6666/tcp, 6667/tcp,
        8087/tcp, 9090/tcp, 9999/tcp, 5555/tcp,
    } &redef;

    const monitored_services: set[port] = {
        21/tcp, 22/tcp, 23/tcp, 3389/tcp, 3306/tcp, 1433/tcp,
    } &redef;
}

global conn_counter: table[addr, addr, port] of count &create_expire=1min &default=0;
global beacon_tracker: table[addr, addr, port] of vector of time &create_expire=30min;

event connection_state_remove(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local dport = c$id$resp_p;
    local service_port = count_to_port(dport, c$id$resp_p);

    if (service_port in monitored_services)
    {
        local key = (orig, resp, dport);
        conn_counter[key] += 1;

        local count = conn_counter[key];
        if (count > high_rate_threshold)
        {
            NOTICE([$note=HighRateConnection,
                    $conn=c,
                    $msg=fmt("%s → %s:%d: %d connections in %s (possible brute force)",
                             orig, resp, dport, count, rate_window),
                    $sub=fmt("service=%s", port_to_str(service_port)),
                    $identifier=cat(orig, resp, dport)]);
        }
    }

    if (service_port in suspicious_ports)
    {
        NOTICE([$note=SuspiciousPortAccess,
                $conn=c,
                $msg=fmt("%s accessed suspicious port %s", orig, port_to_str(service_port)),
                $identifier=cat(orig, resp, dport)]);
    }

    if (c$conn$proto == icmp && c$orig$size > icmp_large_threshold)
    {
        NOTICE([$note=ICMPLargePayload,
                $conn=c,
                $msg=fmt("%s → %s: ICMP payload %d bytes", orig, resp, c$orig$size),
                $identifier=cat(orig, resp)]);
    }

    local orig_bytes = c$orig$num_bytes_ip;
    local resp_bytes = c$resp$num_bytes_ip;
    if (orig_bytes + resp_bytes > 0)
    {
        local ratio = orig_bytes / (orig_bytes + resp_bytes);
        if (ratio > upload_ratio_threshold && orig_bytes > upload_min_bytes)
        {
            NOTICE([$note=UnusualDataUpload,
                    $conn=c,
                    $msg=fmt("%s → %s: %.0f%% upload (%d bytes)",
                             orig, resp, ratio * 100, orig_bytes),
                    $identifier=cat(orig, resp)]);
        }
    }

    if (c$conn$service == "dns" && c$dns$query != "" && |c$dns$query| > 52)
    {
        NOTICE([$note=DNSTunnelSuspect,
                $conn=c,
                $msg=fmt("%s DNS query length %d: %s", orig, |c$dns$query|, c$dns$query),
                $identifier=cat(orig, |c$dns$query|)]);
    }

    local bk = (orig, resp, dport);
    if (bk !in beacon_tracker)
        beacon_tracker[bk] = vector();
    beacon_tracker[bk] += c$start_time;

    if (|beacon_tracker[bk]| >= 5)
    {
        local times = beacon_tracker[bk];
        local deltas: vector of interval;
        for (i in vector(1, |times|-1))
            deltas += times[i] - times[i-1];

        if (|deltas| >= 3)
        {
            local sum: interval = 0sec;
            for (i in deltas) sum += deltas[i];
            local mean = sum / |deltas|;

            local variance: double = 0;
            for (i in deltas)
                variance += (interval_to_double(deltas[i]) - interval_to_double(mean)) ^ 2;
            variance /= |deltas|;
            local std = sqrt(variance);
            local jitter = std / interval_to_double(mean);

            if (jitter < beacon_jitter_threshold && interval_to_double(mean) > 5)
            {
                NOTICE([$note=BeaconBehavior,
                        $conn=c,
                        $msg=fmt("%s → %s:%d: beacon interval %.1fs (jitter %.3f)",
                                 orig, resp, dport, interval_to_double(mean), jitter),
                        $identifier=cat(orig, resp, dport)]);
            }
        }
    }
}

event conn_attempt(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local dport = c$id$resp_p;

    if (dport != 80/tcp && dport != 443/tcp && dport != 53/udp)
        return;

    local key = (orig, resp, dport);
    conn_counter[key] += 1;

    if (conn_counter[key] > 100)
    {
        NOTICE([$note=PortScanActivity,
                $conn=c,
                $msg=fmt("%s: %d connection attempts to %s:%d",
                         orig, conn_counter[key], resp, dport),
                $identifier=cat(orig, resp, dport)]);
    }
}
