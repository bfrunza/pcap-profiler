import  sys
with open('dumps/Drops_CF_All_V3.verbose.txt', 'rt') as file:
    with open('dumps/Drops_CF_All_V3.verbose.txt.out', 'wt') as out_file:
        out = ""
        start = True
        while True:
            line = file.readline()

            if "IP" in line and "21:" in line:
                if not start:
                    out_file.write(out + "\n")
                start = False
                out = line.replace("\n", "")
            else:
                out += line.replace("\n", "")

            if not line:
                out_file.write(out + '\n')
                break