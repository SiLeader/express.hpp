//   Copyright 2019 SiLeader and Cerussite.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

#include "express.hpp"
#include <iostream>

int main() {
    express::Express app;
    app.get("/", [](const express::Request &req, express::Response &res) {
        std::cout << "ok /" << std::endl;
        res.end("ok");
    });

    app.get("/parameters/:id/others/:other",
            [](const express::Request &req, express::Response &res) {
                std::cout << "ok /parameters/" << req.params("id") << "/others/"
                          << req.params("other") << std::endl;
                res.end("ok");
            });

    app.post("/post", [](const express::Request &req, express::Response &res) {
        std::cout << "ok /port " << req.body() << std::endl;
        res.end("ok post");
    });

    app.listen();
    return 0;
}