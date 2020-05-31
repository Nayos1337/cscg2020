def parse(data, port, origin):
    arrow = "c --> s" if origin == "client" else "c <-- s"
    print("{} : {}".format(arrow, data.hex()))
