unshift(@INC, '.');
require 't/t/GenTAP.pm';
GenTAP(0, 0, 'is', 10000);
