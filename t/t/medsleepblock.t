unshift(@INC, '.');
require 't/t/GenTAP.pm';
GenTAP(0.5, 10, 'block', 10000);
