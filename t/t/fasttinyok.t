unshift(@INC, '.');
require 't/t/GenTAP.pm';
GenTAP(0, 0, 'tinyok', 1000000);
