/**
 * 
 */
package com.hkare.openam.auth.nodes.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.forgerock.json.JsonValue;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author manip
 *
 */
public class MyInfoJsonUtil {

	private static final Logger logger = LoggerFactory.getLogger("amAuth");

	/**
	 * @param responseJsonStr
	 * @param string
	 * @return
	 * @throws JSONException
	 * @throws JsonParseException
	 * @throws JsonMappingException
	 * @throws IOException
	 */
	public static JsonValue parseResponseJson(String responseJsonStr, String inputAttributes, String subject)
			throws JSONException, JsonParseException, JsonMappingException, IOException {

		List<String> attributes = new ArrayList<>();

		if (inputAttributes != null) {
			attributes.addAll(Arrays.asList(inputAttributes.split(",")));
		}

		JSONObject obj = new JSONObject(responseJsonStr);
		ObjectMapper mapper = new ObjectMapper();
		Map<String, Object> map = mapper.readValue(responseJsonStr, Map.class);
		logger.debug("parsed Json from response:::" + map);

		Map<String, Object> newMap = new HashMap<String, Object>();

		newMap.put("sub", subject);
		for (String attribute : attributes) {
			Map<String, Object> valueMap = (Map<String, Object>) map.get(attribute);
			logger.debug("value map:" + valueMap);
			// check contains value
			if (valueMap.containsKey("value")) {
				newMap.put(attribute, valueMap.get("value"));
			} else if (valueMap.containsKey("desc")) {
				newMap.put(attribute, valueMap.get("desc"));
			} else {
				// check for specific attributes
				if (attribute.equalsIgnoreCase("mobileno")) {
					newMap.put(attribute, getMobileNo(valueMap));
				}
				if (attribute.equalsIgnoreCase("regadd")) {
					newMap.put(attribute, getRegisteredAddrs(valueMap));
				}
				if (attribute.equalsIgnoreCase("noa-basic")) {
					// getNOABasic(valueMap);
				}
				if (attribute.equalsIgnoreCase("cpfbalances")) {
					// getCPFBalanace(valueMap);
				}
				if (attribute.equalsIgnoreCase("cpfcontributions")) {
					// getCPFContributions(valueMap);
				}
			}
		}
		logger.debug("processed map::" + newMap);
		JsonValue storeJson = new JsonValue(newMap);
		return storeJson;
	}

	/**
	 * @param valueMap
	 * @return
	 */
	private static String getValue(Map<String, Object> valueMap) {
		String value = null;

		if (valueMap != null) {
			if (valueMap.containsKey("value")) {
				value = (valueMap.get("value") != null) ? (String) valueMap.get("value") : "";
			} else if (valueMap.containsKey("desc")) {
				value = (valueMap.get("desc") != null) ? (String) valueMap.get("desc") : "";
			}
		}
		return value;
	}

	/**
	 * @param valueMap
	 * @return
	 */
	private static String getRegisteredAddrs(Map<String, Object> valueMap) {

		String registeredAddrs = null;

		Map<String, Object> countrymap = (Map<String, Object>) valueMap.get("country");
		Map<String, Object> unitmap = (Map<String, Object>) valueMap.get("unit");
		Map<String, Object> streetmap = (Map<String, Object>) valueMap.get("street");
		Map<String, Object> blockmap = (Map<String, Object>) valueMap.get("block");
		Map<String, Object> postalmap = (Map<String, Object>) valueMap.get("postal");
		Map<String, Object> floormap = (Map<String, Object>) valueMap.get("floor");

		String country = getValue(countrymap);
		String unit = getValue(unitmap);
		String street = getValue(streetmap);
		String block = getValue(blockmap);
		String postal = getValue(postalmap);
		String floor = getValue(floormap);

		registeredAddrs = "#" + floor + "-" + unit + "," + block + "," + street + "," + country + " " + postal;

		return registeredAddrs;
	}

	/**
	 * @param valueMap
	 * @return
	 */
	private static String getMobileNo(Map<String, Object> valueMap) {
		String mobileNum = "";

		Map<String, Object> areamap = (Map<String, Object>) valueMap.get("areacode");
		Map<String, Object> prefixmap = (Map<String, Object>) valueMap.get("prefix");
		Map<String, Object> nbrmap = (Map<String, Object>) valueMap.get("nbr");

		String areacode = getValue(areamap);
		String prefix = getValue(prefixmap);
		String nbr = getValue(nbrmap);

		mobileNum = prefix + areacode + " " + nbr;
		logger.debug("mobileNum formed::" + mobileNum);
		return mobileNum;
	}

}
