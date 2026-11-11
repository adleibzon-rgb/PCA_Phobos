package com.pca.phobos.vpn;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * AllowedIPs for "Russian sites directly": the whole IPv4 internet minus the direct set,
 * where direct = Russian networks + the user's "direct" entries - the user's "via VPN" entries.
 * Entries: IP, CIDR or domain (resolved to its current IPv4 addresses).
 */
final class RuNets {
    private RuNets() { }

    static String allowed(List<String> ruCidrs, List<String> direct, List<String> viaVpn) {
        List<long[]> d = new ArrayList<>();
        for (String c : ruCidrs) add(d, c);
        for (String e : direct) for (String c : resolve(e)) add(d, c);
        List<long[]> v = new ArrayList<>();
        for (String e : viaVpn) for (String c : resolve(e)) add(v, c);
        List<long[]> directSet = subtract(merge(d), merge(v));
        // complement over 0.0.0.0 - 255.255.255.255
        List<String> out = new ArrayList<>();
        long next = 0;
        for (long[] r : directSet) {
            if (r[0] > next) cidrs(next, r[0] - 1, out);
            next = Math.max(next, r[1] + 1);
        }
        if (next <= 0xFFFFFFFFL) cidrs(next, 0xFFFFFFFFL, out);
        return String.join(", ", out);
    }

    /** "1.2.3.4", "1.2.3.0/24" or "site.ru" -> CIDRs (empty if it does not resolve). */
    static List<String> resolve(String entry) {
        List<String> out = new ArrayList<>();
        String e = entry.trim().toLowerCase().replaceFirst("^\\w+://", "").replaceFirst("/$", "");
        if (e.isEmpty() || e.startsWith("#")) return out;
        if (e.matches("[0-9.]+(/\\d+)?")) { out.add(e.contains("/") ? e : e + "/32"); return out; }
        e = e.replaceFirst("/.*$", "");
        try {
            for (InetAddress a : InetAddress.getAllByName(e)) if (a instanceof Inet4Address) out.add(a.getHostAddress() + "/32");
        } catch (Exception ignored) { }
        return out;
    }

    private static void add(List<long[]> list, String cidr) {
        try {
            String[] p = cidr.trim().split("/");
            String[] o = p[0].split("\\.");
            if (o.length != 4) return;
            long ip = 0;
            for (String x : o) ip = (ip << 8) | Integer.parseInt(x);
            int bits = p.length > 1 ? Integer.parseInt(p[1]) : 32;
            long size = 1L << (32 - bits);
            long start = ip & ~(size - 1) & 0xFFFFFFFFL;
            list.add(new long[]{start, start + size - 1});
        } catch (Exception ignored) { }
    }

    private static List<long[]> merge(List<long[]> in) {
        Collections.sort(in, (a, b) -> Long.compare(a[0], b[0]));
        List<long[]> out = new ArrayList<>();
        for (long[] r : in) {
            if (!out.isEmpty() && r[0] <= out.get(out.size() - 1)[1] + 1) {
                long[] last = out.get(out.size() - 1);
                last[1] = Math.max(last[1], r[1]);
            } else out.add(new long[]{r[0], r[1]});
        }
        return out;
    }

    private static List<long[]> subtract(List<long[]> a, List<long[]> b) {
        List<long[]> out = new ArrayList<>();
        for (long[] r : a) {
            long s = r[0], e = r[1];
            for (long[] x : b) {
                if (x[1] < s || x[0] > e) continue;
                if (x[0] > s) out.add(new long[]{s, x[0] - 1});
                s = x[1] + 1;
                if (s > e) break;
            }
            if (s <= e) out.add(new long[]{s, e});
        }
        return out;
    }

    private static void cidrs(long start, long end, List<String> out) {
        while (start <= end) {
            int bits = 32;
            while (bits > 0) {
                long size = 1L << (33 - bits);
                if ((start & (size - 1)) != 0 || start + size - 1 > end) break;
                bits--;
            }
            out.add(((start >> 24) & 255) + "." + ((start >> 16) & 255) + "." + ((start >> 8) & 255) + "." + (start & 255) + "/" + bits);
            start += 1L << (32 - bits);
        }
    }
}
