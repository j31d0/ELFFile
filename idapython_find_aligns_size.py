# run this module in ida.
# ALT + F7 and choose this file.


ea = ScreenEA()

end = SegStart(ea)
empty_space = []
functions = [function for function in Functions(SegStart(ea), SegEnd(ea))]

for function_ea in functions:
    start, _end = function_ea, FindFuncEnd(function_ea)    
    if end != start:
        empty_space.append((end, start - end))
    end = _end
    print hex(start), hex(end)

empty_space = sorted(empty_space, key = lambda x: x[1])
for addr, size in empty_space:
    print hex(addr), ":", size

