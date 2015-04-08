unshift(@INC, '.');
require 't/t/GenTAP.pm';
GenTAP(0, 0, 'print', 1000000);
