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
package org.ice4j.stack;

/**
 * Generic Error Handler.
 *
 *  通用错误处理的回调 ...
 * @author Emil Ivov
 */
interface ErrorHandler
{
    /**
     * Called when an error has occurred which may have caused data loss but the
     * calling thread is still running.
     *
     * 例如错误出现(数据丢失,但是调用线程仍在运行) 时触发 。。
     *
     * @param message A message describing the error
     * @param error   The error itself.
     */
    public void handleError(String message, Throwable error);

    /**
     * Called when a fatal error has occurred and the calling thread will exit.
     * 出现了一个致命错误且调用线程将会退出 调用 ...此回调 ..
     * @param callingThread the thread where the error has occurred
     * @param message       a message describing the error.
     * @param error         the error itself.
     */
    public void handleFatalError(Runnable callingThread,
                                 String message,
                                 Throwable error);
}
