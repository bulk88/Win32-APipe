unshift(@INC, '.');
require 't/t/GenTAP.pm';
GenTAP(0, 0, 'ok', 1000000);
