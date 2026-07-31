#!/usr/bin/env python3
# MaskGen - Generate Password Masks
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.3
#
# Copyright (C) 2013 Peter Kacherginsky
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.

import csv
import datetime
from optparse import OptionParser, OptionGroup

VERSION = "0.0.3"


class MaskGen:
    def __init__(self):
        # Masks collections with meta data
        self.masks = dict()

        self.target_time = None
        self.output_file = None

        self.minlength = None
        self.maxlength = None
        self.mintime = None
        self.maxtime = None
        self.mincomplexity = None
        self.maxcomplexity = None
        self.minoccurrence = None
        self.maxoccurrence = None

        self.customcharset1len = None
        self.customcharset2len = None
        self.customcharset3len = None
        self.customcharset4len = None

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

        # Counter for total masks coverage
        self.total_occurrence = 0

    def getcomplexity(self, mask):
        """ Return mask complexity, or None if the mask cannot be costed. """
        count = 1
        for char in mask[1:].split("?"):
            if char == "l":
                count *= 26
            elif char == "u":
                count *= 26
            elif char == "d":
                count *= 10
            elif char == "s":
                count *= 33
            elif char == "a":
                count *= 95
            elif char == "b":
                count *= 256
            elif char == "h" or char == "H":
                count *= 16
            elif char == "1" and self.customcharset1len:
                count *= self.customcharset1len
            elif char == "2" and self.customcharset2len:
                count *= self.customcharset2len
            elif char == "3" and self.customcharset3len:
                count *= self.customcharset3len
            elif char == "4" and self.customcharset4len:
                count *= self.customcharset4len
            else:
                # An uncostable token (a literal, or ?1-?4 with no declared
                # length) would silently understate complexity and runtime, so
                # refuse the mask instead of guessing.
                print("[!] Error, unknown mask ?%s in a mask %s" % (char, mask))
                return None

        return count

    def loadmasks(self, filename):
        """ Load masks and apply filters. """
        with open(filename, 'r') as mask_file:
            for (mask, occurrence) in csv.reader(mask_file, delimiter=',', quotechar='"'):

                if not mask:
                    continue

                mask_occurrence = int(occurrence)
                mask_length = len(mask) // 2
                mask_complexity = self.getcomplexity(mask)

                if mask_complexity is None:
                    print("[!] Skipping mask %s: complexity cannot be determined." % mask)
                    continue

                mask_time = mask_complexity / self.pps

                self.total_occurrence += mask_occurrence

                # A mask repeated across input files accumulates occurrences;
                # otherwise coverage is reported against a total it can never
                # reach.
                if mask in self.masks:
                    self.masks[mask]['occurrence'] += mask_occurrence
                    self.masks[mask]['optindex'] = 1 - (mask_complexity / self.masks[mask]['occurrence'])
                    continue

                # Apply filters based on occurrence, length, complexity and time
                if (self.minoccurrence is None or mask_occurrence >= self.minoccurrence) and \
                   (self.maxoccurrence is None or mask_occurrence <= self.maxoccurrence) and \
                   (self.mincomplexity is None or mask_complexity >= self.mincomplexity) and \
                   (self.maxcomplexity is None or mask_complexity <= self.maxcomplexity) and \
                   (self.mintime is None or mask_time >= self.mintime) and \
                   (self.maxtime is None or mask_time <= self.maxtime) and \
                   (self.maxlength is None or mask_length <= self.maxlength) and \
                   (self.minlength is None or mask_length >= self.minlength):

                    self.masks[mask] = dict()
                    self.masks[mask]['length'] = mask_length
                    self.masks[mask]['occurrence'] = mask_occurrence
                    self.masks[mask]['complexity_raw'] = mask_complexity
                    # Negated so that reverse-sorting yields cheapest-first.
                    self.masks[mask]['complexity'] = 1 - mask_complexity
                    self.masks[mask]['time'] = mask_time
                    self.masks[mask]['optindex'] = 1 - (mask_complexity / mask_occurrence)

    def generate_masks(self, sorting_mode):
        """ Generate optimal password masks sorted by occurrence, complexity or optindex """
        sample_count = 0
        sample_time = 0
        sample_occurrence = 0

        # TODO Group by time here 1 minutes, 1 hour, 1 day, 1 month, 1 year....
        #      Group by length   1,2,3,4,5,6,7,8,9,10....
        #      Group by occurrence 10%, 20%, 30%, 40%, 50%....

        if self.showmasks:
            print("[L:] Mask:                          [ Occ:  ] [ Time:  ]")

        for mask in sorted(self.masks.keys(), key=lambda m: self.masks[m][sorting_mode], reverse=True):

            # Stop before emitting a mask that would overshoot the budget,
            # so every mask written is one the caller has time to run.
            if self.target_time and sample_time + self.masks[mask]['time'] > self.target_time:
                print("[!] Target time exceeded.")
                break

            if self.showmasks:
                time_human = ">1 year" if self.masks[mask]['time'] > 60*60*24*365 \
                    else str(datetime.timedelta(seconds=self.masks[mask]['time']))
                print("[{:>2}] {:<30} [{:<7}] [{:>8}]  ".format(self.masks[mask]['length'], mask,
                                                                self.masks[mask]['occurrence'], time_human))

            if self.output_file:
                self.output_file.write("%s\n" % mask)

            sample_occurrence += self.masks[mask]['occurrence']
            sample_time += self.masks[mask]['time']
            sample_count += 1

        print("[*] Finished generating masks:")
        print("    Masks generated: %s" % sample_count)
        print("    Masks coverage:  %d%% (%d/%d)" % (self.coverage_percent(sample_occurrence),
                                                     sample_occurrence, self.total_occurrence))
        time_human = ">1 year" if sample_time > 60*60*24*365 else str(datetime.timedelta(seconds=sample_time))
        print("    Masks runtime:   %s" % time_human)

    def coverage_percent(self, sample_occurrence):
        """ Percentage of all loaded occurrences covered by the sample. """
        if not self.total_occurrence:
            return 0
        return sample_occurrence * 100 // self.total_occurrence

    def getmaskscoverage(self, checkmasks):

        sample_count = 0
        sample_occurrence = 0

        total_complexity = 0

        if self.showmasks:
            print("[L:] Mask:                          [ Occ:  ] [ Time:  ]")

        for mask in checkmasks:
            mask = mask.strip()

            if not mask:
                continue

            mask_complexity = self.getcomplexity(mask)

            if mask_complexity is None:
                print("[!] Skipping mask %s: complexity cannot be determined." % mask)
                continue

            total_complexity += mask_complexity

            if mask in self.masks:

                if self.showmasks:
                    time_human = ">1 year" if self.masks[mask]['time'] > 60*60*24*365 \
                        else str(datetime.timedelta(seconds=self.masks[mask]['time']))
                    print("[{:>2}] {:<30} [{:<7}] [{:>8}]  ".format(self.masks[mask]['length'], mask,
                                                                    self.masks[mask]['occurrence'], time_human))

                if self.output_file:
                    self.output_file.write("%s\n" % mask)

                sample_occurrence += self.masks[mask]['occurrence']
                sample_count += 1

            if self.target_time and total_complexity / self.pps > self.target_time:
                print("[!] Target time exceeded.")
                break

        total_time = total_complexity / self.pps
        time_human = ">1 year" if total_time > 60*60*24*365 else str(datetime.timedelta(seconds=total_time))
        print("[*] Finished matching masks:")
        print("    Masks matched: %s" % sample_count)
        print("    Masks coverage:  %d%% (%d/%d)" % (self.coverage_percent(sample_occurrence),
                                                     sample_occurrence, self.total_occurrence))
        print("    Masks runtime:   %s" % time_human)


if __name__ == "__main__":

    header =   "                       _ \n"
    header +=  "     MaskGen %s    | |\n" % VERSION
    header +=  "      _ __   __ _  ___| | _\n"
    header += r"     | '_ \ / _` |/ __| |/ /" + "\n"
    header +=  "     | |_) | (_| | (__|   < \n"
    header += r"     | .__/ \__,_|\___|_|\_\ " + "\n"
    header +=  "     | |                    \n"
    header +=  "     |_| iphelix@thesprawl.org\n"
    header +=  "\n"

    parser = OptionParser("%prog pass0.masks [pass1.masks ...] [options]", version="%prog "+VERSION)

    parser.add_option("-t", "--targettime",  dest="target_time",  type="int", metavar="86400",
                      help="Target time of all masks (seconds)")
    parser.add_option("-o", "--outputmasks", dest="output_masks", metavar="masks.hcmask",
                      help="Save masks to a file")

    filters = OptionGroup(parser, "Individual Mask Filter Options")
    filters.add_option("--minlength", dest="minlength", type="int", metavar="8", help="Minimum password length")
    filters.add_option("--maxlength", dest="maxlength", type="int", metavar="8", help="Maximum password length")
    filters.add_option("--mintime", dest="mintime", type="int", metavar="3600", help="Minimum mask runtime (seconds)")
    filters.add_option("--maxtime", dest="maxtime", type="int", metavar="3600", help="Maximum mask runtime (seconds)")
    filters.add_option("--mincomplexity", dest="mincomplexity", type="int", metavar="1", help="Minimum complexity")
    filters.add_option("--maxcomplexity", dest="maxcomplexity", type="int", metavar="100", help="Maximum complexity")
    filters.add_option("--minoccurrence", dest="minoccurrence", type="int", metavar="1", help="Minimum occurrence")
    filters.add_option("--maxoccurrence", dest="maxoccurrence", type="int", metavar="100", help="Maximum occurrence")
    parser.add_option_group(filters)

    sorting = OptionGroup(parser, "Mask Sorting Options")
    sorting.add_option("--optindex", action="store_true", dest="optindex", help="sort by mask optindex (default)",
                       default=False)
    sorting.add_option("--occurrence", action="store_true", dest="occurrence", help="sort by mask occurrence",
                       default=False)
    sorting.add_option("--complexity", action="store_true", dest="complexity", help="sort by mask complexity",
                       default=False)
    parser.add_option_group(sorting)

    coverage = OptionGroup(parser, "Check mask coverage")
    coverage.add_option("--checkmasks", dest="checkmasks", help="check mask coverage",
                        metavar="?u?l?l?l?l?l?d,?l?l?l?l?l?d?d")
    coverage.add_option("--checkmasksfile", dest="checkmasks_file", help="check mask coverage in a file",
                        metavar="masks.hcmask")
    parser.add_option_group(coverage)

    parser.add_option("--showmasks", dest="showmasks", help="Show matching masks", action="store_true", default=False)

    custom = OptionGroup(parser, "Custom character set options")
    custom.add_option("--custom-charset1-len", dest="customcharset1len", type="int", metavar="26",
                      help="Length of custom character set 1")
    custom.add_option("--custom-charset2-len", dest="customcharset2len", type="int", metavar="26",
                      help="Length of custom character set 2")
    custom.add_option("--custom-charset3-len", dest="customcharset3len", type="int", metavar="26",
                      help="Length of custom character set 3")
    custom.add_option("--custom-charset4-len", dest="customcharset4len", type="int", metavar="26",
                      help="Length of custom character set 4")
    parser.add_option_group(custom)

    misc = OptionGroup(parser, "Miscellaneous options")
    misc.add_option("--pps", dest="pps", help="Passwords per Second", type="int", metavar="1000000000")
    misc.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False, help="Don't show headers.")
    parser.add_option_group(misc)

    (options, args) = parser.parse_args()

    # Print program header
    if not options.quiet: 
        print(header)

    if len(args) < 1:
        parser.error("no masks file specified! Please provide statsgen output.")
        exit(1)

    print("[*] Analyzing masks in [%s]" % args[0])

    maskgen = MaskGen()

    # Settings
    # NOTE: compare against None throughout; a legitimate 0 must not be
    #       silently discarded as falsey.
    if options.target_time is not None:
        maskgen.target_time = options.target_time
    if options.output_masks:
        print("[*] Saving generated masks to [%s]" % options.output_masks)
        maskgen.output_file = open(options.output_masks, 'w')

    # Filters
    if options.minlength is not None:
        maskgen.minlength = options.minlength
    if options.maxlength is not None:
        maskgen.maxlength = options.maxlength
    if options.mintime is not None:
        maskgen.mintime = options.mintime
    if options.maxtime is not None:
        maskgen.maxtime = options.maxtime
    if options.mincomplexity is not None:
        maskgen.mincomplexity = options.mincomplexity
    if options.maxcomplexity is not None:
        maskgen.maxcomplexity = options.maxcomplexity
    if options.minoccurrence is not None:
        maskgen.minoccurrence = options.minoccurrence
    if options.maxoccurrence is not None:
        maskgen.maxoccurrence = options.maxoccurrence

    # Custom character sets
    if options.customcharset1len is not None:
        maskgen.customcharset1len = options.customcharset1len
    if options.customcharset2len is not None:
        maskgen.customcharset2len = options.customcharset2len
    if options.customcharset3len is not None:
        maskgen.customcharset3len = options.customcharset3len
    if options.customcharset4len is not None:
        maskgen.customcharset4len = options.customcharset4len

    # Misc
    if options.pps is not None:
        if options.pps <= 0:
            parser.error("--pps must be greater than 0")
        maskgen.pps = options.pps
    if options.showmasks:
        maskgen.showmasks = options.showmasks

    print("[*] Using {:,d} keys/sec for calculations.".format(maskgen.pps))
    
    # Load masks
    for arg in args:
        maskgen.loadmasks(arg)

    # Matching masks from the command-line
    if options.checkmasks:
        checkmasks = [m.strip() for m in options.checkmasks.split(',')]
        print("[*] Checking coverage of the these masks [%s]" % ", ".join(checkmasks))
        maskgen.getmaskscoverage(checkmasks)

    # Matching masks from a file
    elif options.checkmasks_file:
        checkmasks_file = open(options.checkmasks_file, 'r')
        print("[*] Checking coverage of masks in [%s]" % options.checkmasks_file)
        maskgen.getmaskscoverage(checkmasks_file)

    # Printing masks in a file
    else:
        # Process masks according to specified sorting algorithm
        if options.occurrence: 
            sort_mode = "occurrence"
        elif options.complexity: 
            sort_mode = "complexity"
        else: 
            sort_mode = "optindex"

        print("[*] Sorting masks by their [%s]." % sort_mode)
        maskgen.generate_masks(sort_mode)
