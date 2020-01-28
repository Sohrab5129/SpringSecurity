<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Login Page</title>

<%-- <script src="<c:url value="/resources/static/js/main.js"/>"></script> --%>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
   
<script type="text/javascript">
window.history.forward();
function noBack() {
	window.history.forward();
}
</script>

</head>
<body onload="noBack();" onpageshow="if (event.persisted) noBack();"
	onunload="" oncontextmenu="return false;">
	
	<h3>Login Page</h3>




</body>
</html>