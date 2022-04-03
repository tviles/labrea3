-- Adminer 4.7.1 MySQL dump

SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

SET NAMES utf8mb4;

CREATE DATABASE `labrea` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;
USE `labrea`;

CREATE TABLE `packets` (
  `timestamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' ON UPDATE current_timestamp(),
  `ether.dst` char(17) DEFAULT NULL,
  `ether.src` char(17) DEFAULT NULL,
  `ether.type` varchar(5) DEFAULT NULL,
  `ip.version` varchar(2) DEFAULT NULL,
  `ip.ihl` varchar(2) DEFAULT NULL,
  `ip.tos` varchar(3) DEFAULT NULL,
  `ip.len` varchar(5) DEFAULT NULL,
  `ip.id` varchar(5) DEFAULT NULL,
  `ip.flags` text DEFAULT NULL,
  `ip.frag` varchar(4) DEFAULT NULL,
  `ip.ttl` varchar(3) DEFAULT NULL,
  `ip.proto` varchar(3) DEFAULT NULL,
  `ip.chksum` varchar(5) DEFAULT NULL,
  `ip.src` varchar(15) DEFAULT NULL,
  `ip.dst` varchar(15) DEFAULT NULL,
  `ip.options` text DEFAULT NULL,
  `tcp.sport` varchar(5) DEFAULT NULL,
  `tcp.dport` varchar(5) DEFAULT NULL,
  `tcp.seq` varchar(10) DEFAULT NULL,
  `tcp.ack` varchar(10) DEFAULT NULL,
  `tcp.dataofs` varchar(2) DEFAULT NULL,
  `tcp.reserved` varchar(2) DEFAULT NULL,
  `tcp.flags` text DEFAULT NULL,
  `tcp.window` varchar(5) DEFAULT NULL,
  `tcp.chksum` varchar(5) DEFAULT NULL,
  `tcp.urgptr` varchar(5) DEFAULT NULL,
  `tcp.options` text DEFAULT NULL,
  `raw.load` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- 2022-04-03 19:31:45
