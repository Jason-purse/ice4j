/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j;

/**
 * 这个接口 在发送一个请求的时候用作一个回调 ... 这个响应收集器 被用来 打算派发响应 ...
 * The interface is used as a callback when sending a request. The response
 * collector is then used as a means of dispatching the response.
 *
 * @author Emil Ivov
 */
public interface ResponseCollector
{
    /**
     * Dispatch the specified response.
     *
     * @param event the response to dispatch.
     */
    public void processResponse(StunResponseEvent event);

    /**
     * Notifies this collector that no response had been received after repeated
     * retransmissions of the original request (as described by rfc3489) and
     * that the request should be considered unanswered.
     *
     * 通知这个收集器这里没有响应得到回应(原始请求重复多次) - rfc 3489描述 那么这个请求将会考虑为未应答 ...
     *
     * @param event the <tt>StunTimeoutEvent</tt> containing a reference to the
     * transaction that has just failed.
     */
    public void processTimeout(StunTimeoutEvent event);
}
