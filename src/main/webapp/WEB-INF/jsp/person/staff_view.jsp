<%-- 
    Document   : staff_view
    Created on : 17.01.2012, 11:09:37
    Author     : Aljona Murygina
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@taglib prefix="joda" uri="http://www.joda.org/joda/time/tags" %>
<%@taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@taglib prefix="uv" tagdir="/WEB-INF/tags" %>
<%@taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>


<!DOCTYPE html>
<html>

    <head>
        <uv:head />

        <spring:url var="formUrlPrefix" value="/web" />

        <c:choose>
            <c:when test="${!empty param.year}">
                <c:set var="displayYear" value="${param.year}" />
            </c:when>
            <c:otherwise>
                <c:set var="displayYear" value="${year}" />
            </c:otherwise>
        </c:choose>
        
        <script type="text/javascript">
            $(document).ready(function() {

                $("table.sortable").tablesorter({
                    sortList: [[0,0]],
                    headers: {
                      5: { sorter: 'commaNumber' }, 
                      6: { sorter: 'commaNumber' }
                    }
                });
                
                var path = window.location.pathname;

                var active;
                
                if(path.indexOf("inactive") != -1) {
                    $("div#active-state button").html('<i class="fa fa-toggle-off"></i>&nbsp;<spring:message code="table.inactive" />&nbsp;<span class="caret"></span>');
                } else {
                    $("div#active-state button").html('<i class="fa fa-toggle-on"></i>&nbsp;<spring:message code="table.active" />&nbsp;<span class="caret"></span>');
                }

            });
        </script>
    </head>

    <body>

        <uv:menu />

        <div class="content">
            <div class="container">

                <div class="row">

                    <div class="col-xs-12">

                    <div class="header">

                        <legend class="sticky">
                            
                            <p>
                                <spring:message code="table.overview" /><c:out value="${displayYear}" />
                            </p>

                            <uv:year-selector year="${year}" />

                            <div id="active-state" class="btn-group pull-right">

                                <button class="btn btn-default dropdown-toggle" data-toggle="dropdown">
                                </button>

                                <ul class="dropdown-menu">
                                    <li>
                                        <a href="${formUrlPrefix}/staff">
                                            <i class="fa fa-toggle-on"></i>
                                            <spring:message code="table.active" />
                                        </a>
                                    </li>
                                    <li>
                                        <a href="${formUrlPrefix}/staff/inactive">
                                            <i class="fa fa-toggle-off"></i>
                                            <spring:message code="table.inactive" />
                                        </a>
                                    </li>
                                </ul>

                            </div>

                            <uv:print />

                            <sec:authorize access="hasRole('OFFICE')">
                                <a class="btn btn-default pull-right" href="${formUrlPrefix}/staff/new"><i class="fa fa-plus"></i>&nbsp;<spring:message code="table.new.person" /></a>
                            </sec:authorize>
                            
                        </legend>

                    </div>
                    
                    <c:choose>

                        <c:when test="${notexistent == true}">

                            <spring:message code="table.empty" />

                        </c:when>

                        <c:otherwise>
                            <%@include file="./include/staff_list.jsp" %>
                        </c:otherwise>

                    </c:choose>

                    </div>
                </div>
            </div> 
        </div>        

    </body>

</html>
