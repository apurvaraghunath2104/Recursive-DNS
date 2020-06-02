"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse
import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 23 February 2017
ROOT_SERVERS = ("198.41.0.4",
                "192.228.79.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

domain_cache = {}


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    cnames = []
    arecords = []
    aaaarecords = []
    mxrecords = []

    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)

    if response is not None:
        for answers in response.answer:
            for answer in answers:
                cnames.append({"name": answer, "alias": name})

                # Use CNAME answer for the remaining lookups
                target_name = str(answer)[:-1]

    # lookup A
    response = lookup(target_name, dns.rdatatype.A)

    if response is not None:
        for answers in response.answer:
            a_name = answers.name
            for answer in answers:
                if answer.rdtype == 1:  # A record
                    arecords.append({"name": a_name, "address": str(answer)})

    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)

    if response is not None:
        for answers in response.answer:
            aaaa_name = answers.name
            for answer in answers:
                if answer.rdtype == 28:  # AAAA record
                    aaaarecords.append(
                        {"name": aaaa_name, "address": str(answer)})

    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)

    if response is not None:
        for answers in response.answer:
            mx_name = answers.name
            for answer in answers:
                if answer.rdtype == 15:  # MX record
                    mxrecords.append({"name": mx_name,
                                      "preference": answer.preference,
                                      "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


dict_cache = {}


def ipv4_addr(string):
    ipv4_address = string.split()
    ipv4_list = []
    for row in ipv4_address:
        if row == 'A':
            domain = ipv4_address[0].split(".")
            ipv4_list = [ipv4_address[-1]]
            if domain[-2] not in dict_cache:
                dict_cache[domain[-2]] = ipv4_list
            else:
                if ipv4_list[0] not in dict_cache[domain[-2]]:
                    key = domain[-2]
                    dict_cache[key] = dict_cache[key] + ipv4_list
    return ipv4_list


def lookup(target_name: dns.name.Name, qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.
    """
    tld = str(target_name).split(".")
    domain1 = tld[-2]
    if domain1 in dict_cache:
        cache_ip_address = dict_cache.get(domain1)
        return recursive_resolver(target_name, qtype, cache_ip_address)
    else:
        return recursive_resolver(target_name, qtype, ROOT_SERVERS)


def recursive_resolver(target_name, qtype, servers):
    """
    Recursive DNS resolver function.
    """
    if not servers:
        return None
    outbound_query = dns.message.make_query(target_name, qtype)
    for each_server in servers:
        try:
            response = dns.query.udp(outbound_query, each_server, 3)
        except:
            continue

        if len(response.answer) > 0:
            for answers in response.answer:
                for each_answer in answers:
                    target_name = str(each_answer)[:-1]
                    if each_answer.rdtype == qtype:
                        return response
                    else:
                        if each_answer.rdtype == 5:
                            return recursive_resolver(target_name, qtype, ROOT_SERVERS)
        else:
            address_list = []
            if len(response.additional) > 0:
                for record in response.additional:
                    address_list = address_list + ipv4_addr(str(record))
                return recursive_resolver(target_name, qtype, address_list)
            else:
                ns_list = []
                for auth_list in response.authority:
                    for each_auth in auth_list:
                        if each_auth.rdtype == 6:
                            return None
                        ns_list = ns_list + [str(each_auth)[:-1]]
                    for each_name in ns_list:
                        ns_result = recursive_resolver(each_name, 1, ROOT_SERVERS)
                        if ns_result is not None:
                            for each_answer in ns_result.answer:
                                ns_address = ipv4_addr(str(each_answer))
                                ns_next_res = recursive_resolver(target_name, qtype, ns_address)
                                if ns_next_res is not None:
                                    return ns_next_res


def print_results(results: dict) -> None:
    """
    Take the results of a `lookup` and print them to the screen like the host
    program would.
    """
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    argument_list = []
    if len(program_args.name) <= 1:
        for a_domain_name in program_args.name:
            if a_domain_name in domain_cache:
                print_results(domain_cache[a_domain_name])
            else:
                domain_cache[a_domain_name] = collect_results(a_domain_name)
                print_results(domain_cache[a_domain_name])
    else:
        if len(program_args.name) > 1:
            for x in program_args.name:
                if x not in argument_list:
                    argument_list.append(x)
            for a_domain_name in argument_list:
                if a_domain_name in domain_cache:
                    print_results(domain_cache[a_domain_name])
                else:
                    domain_cache[a_domain_name] = collect_results(a_domain_name)
                    print_results(domain_cache[a_domain_name])
        else:
            for a_domain_name in program_args.name:
                if a_domain_name in domain_cache:
                    print_results(domain_cache[a_domain_name])
                else:
                    domain_cache[a_domain_name] = collect_results(a_domain_name)
                    print_results(domain_cache[a_domain_name])


if __name__ == "__main__":
    main()
