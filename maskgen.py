#!/usr/bin/env python3
# MaskGen - Generate Password Masks
#
# This tool is part of PACK (Password Analysis and Cracking Kit)
#
# VERSION 0.0.4
#
# Copyright (C) 2013 Peter Kacherginsky
# All rights reserved.
#
# Please see the attached LICENSE file for additional licensing information.

import argparse
import csv
import datetime

VERSION = "0.0.4"


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

        # PPS (Passwords per Second) Cracking Speed
        self.pps = 1000000000
        self.showmasks = False

        # Counter for total masks coverage
        self.total_occurrence = 0

    @staticmethod
    def getcomplexity(mask):
        """ Return mask complexity. """
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
            else:
                print("[!] Error, unknown mask ?%s in a mask %s" % (char, mask))

        return count

    def loadmasks(self, filename):
        """ Load masks and apply filters. """
        with open(filename, 'r') as mask_file:
            mask_reader = csv.reader(mask_file, delimiter=',', quotechar='"')

            for (mask, occurrence) in mask_reader:

                if not mask:
                    continue

                mask_occurrence = int(occurrence)
                mask_length = len(mask) // 2
                mask_complexity = self.getcomplexity(mask)
                mask_time = mask_complexity // self.pps

                self.total_occurrence += mask_occurrence

                # Apply filters based on occurrence, length, complexity and time
                if (self.minoccurrence is None or mask_occurrence >= self.minoccurrence) and \
                   (self.maxoccurrence is None or mask_occurrence <= self.maxoccurrence) and \
                   (self.mincomplexity is None or mask_complexity <= self.mincomplexity) and \
                   (self.maxcomplexity is None or mask_complexity <= self.maxcomplexity) and \
                   (self.mintime is None or mask_time <= self.mintime) and \
                   (self.maxtime is None or mask_time <= self.maxtime) and \
                   (self.maxlength is None or mask_length <= self.maxlength) and \
                   (self.minlength is None or mask_length >= self.minlength):

                    self.masks[mask] = dict()
                    self.masks[mask]['length'] = mask_length
                    self.masks[mask]['occurrence'] = mask_occurrence
                    self.masks[mask]['complexity'] = 1 - mask_complexity
                    self.masks[mask]['time'] = mask_time
                    self.masks[mask]['optindex'] = 1 - (mask_complexity // mask_occurrence)

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

            if self.target_time and sample_time > self.target_time:
                print("[!] Target time exceeded.")
                break

        coverage = sample_occurrence * 100 // self.total_occurrence if self.total_occurrence else 0
        print("[*] Finished generating masks:")
        print("    Masks generated: %s" % sample_count)
        print("    Masks coverage:  %d%% (%d/%d)" % (coverage, sample_occurrence, self.total_occurrence))
        time_human = ">1 year" if sample_time > 60*60*24*365 else str(datetime.timedelta(seconds=sample_time))
        print("    Masks runtime:   %s" % time_human)

    def getmaskscoverage(self, checkmasks):

        sample_count = 0
        sample_occurrence = 0

        total_complexity = 0

        if self.showmasks:
            print("[L:] Mask:                          [ Occ:  ] [ Time:  ]")

        for mask in checkmasks:
            mask = mask.strip()
            mask_complexity = self.getcomplexity(mask)

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

        # TODO: Something wrong here, complexity and time doesn't match with estimated from policygen
        total_time = total_complexity / self.pps
        time_human = ">1 year" if total_time > 60*60*24*365 else str(datetime.timedelta(seconds=total_time))
        coverage = sample_occurrence * 100 // self.total_occurrence if self.total_occurrence else 0
        print("[*] Finished matching masks:")
        print("    Masks matched: %s" % sample_count)
        print("    Masks coverage:  %d%% (%d/%d)" % (coverage, sample_occurrence, self.total_occurrence))
        print("    Masks runtime:   %s" % time_human)


def main():

    header = r"""                       _
     MaskGen %s    | |
      _ __   __ _  ___| | _
     | '_ \ / _` |/ __| |/ /
     | |_) | (_| | (__|   <
     | .__/ \__,_|\___|_|\_\
     | |
     |_| iphelix@thesprawl.org
""" % VERSION

    parser = argparse.ArgumentParser(
        description="Generate optimal password masks from statsgen output.")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    parser.add_argument("masks_files", metavar="pass0.masks", nargs="+",
                        help="One or more statsgen mask files to analyze.")

    parser.add_argument("-t", "--targettime", dest="target_time", type=int, metavar="86400",
                        help="Target time of all masks (seconds)")
    parser.add_argument("-o", "--outputmasks", dest="output_masks", metavar="masks.hcmask",
                        help="Save masks to a file")

    filters = parser.add_argument_group("Individual Mask Filter Options")
    filters.add_argument("--minlength", type=int, metavar="8", help="Minimum password length")
    filters.add_argument("--maxlength", type=int, metavar="8", help="Maximum password length")
    filters.add_argument("--mintime", type=int, metavar="3600", help="Minimum mask runtime (seconds)")
    filters.add_argument("--maxtime", type=int, metavar="3600", help="Maximum mask runtime (seconds)")
    filters.add_argument("--mincomplexity", type=int, metavar="1", help="Minimum complexity")
    filters.add_argument("--maxcomplexity", type=int, metavar="100", help="Maximum complexity")
    filters.add_argument("--minoccurrence", type=int, metavar="1", help="Minimum occurrence")
    filters.add_argument("--maxoccurrence", type=int, metavar="100", help="Maximum occurrence")

    sorting = parser.add_argument_group("Mask Sorting Options")
    sorting.add_argument("--optindex", action="store_true", help="sort by mask optindex (default)")
    sorting.add_argument("--occurrence", action="store_true", help="sort by mask occurrence")
    sorting.add_argument("--complexity", action="store_true", help="sort by mask complexity")

    coverage = parser.add_argument_group("Check mask coverage")
    coverage.add_argument("--checkmasks", metavar="?u?l?l?l?l?l?d,?l?l?l?l?l?d?d",
                          help="check mask coverage")
    coverage.add_argument("--checkmasksfile", dest="checkmasks_file", metavar="masks.hcmask",
                          help="check mask coverage in a file")

    parser.add_argument("--showmasks", action="store_true", help="Show matching masks")

    misc = parser.add_argument_group("Miscellaneous options")
    misc.add_argument("--pps", type=int, metavar="1000000000", help="Passwords per Second")
    misc.add_argument("-q", "--quiet", action="store_true", help="Don't show headers.")

    options = parser.parse_args()
    args = options.masks_files

    # Print program header
    if not options.quiet:
        print(header)

    print("[*] Analyzing masks in [%s]" % args[0])

    maskgen = MaskGen()

    # Settings
    if options.target_time:
        maskgen.target_time = options.target_time
    if options.output_masks:
        print("[*] Saving generated masks to [%s]" % options.output_masks)
        maskgen.output_file = open(options.output_masks, 'w')

    # Filters
    if options.minlength:
        maskgen.minlength = options.minlength
    if options.maxlength:
        maskgen.maxlength = options.maxlength
    if options.mintime:
        maskgen.mintime = options.mintime
    if options.maxtime:
        maskgen.maxtime = options.maxtime
    if options.mincomplexity:
        maskgen.mincomplexity = options.mincomplexity
    if options.maxcomplexity:
        maskgen.maxcomplexity = options.maxcomplexity
    if options.minoccurrence:
        maskgen.minoccurrence = options.minoccurrence
    if options.maxoccurrence:
        maskgen.maxoccurrence = options.maxoccurrence

    # Misc
    if options.pps:
        maskgen.pps = options.pps
    if options.showmasks:
        maskgen.showmasks = options.showmasks

    print("[*] Using {:,d} keys/sec for calculations.".format(maskgen.pps))
    
    # Load masks
    for arg in args:
        maskgen.loadmasks(arg)

    try:
        # Matching masks from the command-line
        if options.checkmasks:
            checkmasks = [m.strip() for m in options.checkmasks.split(',')]
            print("[*] Checking coverage of the these masks [%s]" % ", ".join(checkmasks))
            maskgen.getmaskscoverage(checkmasks)

        # Matching masks from a file
        elif options.checkmasks_file:
            print("[*] Checking coverage of masks in [%s]" % options.checkmasks_file)
            with open(options.checkmasks_file, 'r') as checkmasks_file:
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
    finally:
        if maskgen.output_file:
            maskgen.output_file.close()


if __name__ == "__main__":
    main()
